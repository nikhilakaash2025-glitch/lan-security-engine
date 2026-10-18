"""DNS anomaly detection for offline packet-capture analysis."""

import ipaddress
import json
import time
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR


class DNSDetector:
    """Detect unexpected DNS answers and suspicious DNS responses."""

    QUERY_TIMEOUT = 5.0
    CONFLICT_WINDOW = 30.0

    def __init__(self, config_path="dns_config.json", trusted_records=None):
        self.config = {}
        config_file = Path(config_path)

        if config_file.is_file():
            with config_file.open("r", encoding="utf-8") as file:
                self.config = json.load(file)

        self.settings = self.config.get("detection_settings", {})
        self.allowed_dns_servers = set(
            self.config.get("allowed_dns_servers", [])
        )

        self.expected_dns_answers = {}
        for domain, ips in self.config.get("expected_dns_answers", {}).items():
            values = ips if isinstance(ips, (list, tuple, set)) else [ips]
            self.expected_dns_answers[domain.lower().rstrip(".")] = {
                str(ip) for ip in values
            }

        if trusted_records:
            for domain, ips in trusted_records.items():
                values = ips if isinstance(ips, (list, tuple, set)) else [ips]
                self.expected_dns_answers[domain.lower().rstrip(".")] = {
                    str(ip) for ip in values
                }

        self.ledger = {}
        self.pending_queries = {}
        self.recent_answers = {}
        self._expired_queries = {}

    @staticmethod
    def _domain(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return str(value or "").rstrip(".").lower()

    @staticmethod
    def _record_type(value):
        if isinstance(value, str):
            return value.upper()

        return {
            1: "A",
            28: "AAAA",
            5: "CNAME",
            15: "MX",
            16: "TXT",
        }.get(int(value), str(value))

    @staticmethod
    def _normalize_ipv4(value):
        try:
            return str(ipaddress.IPv4Address(value))
        except (ipaddress.AddressValueError, TypeError, ValueError):
            return None

    @staticmethod
    def _packet_questions(dns):
        """Extract DNS questions from Scapy list or chained fields."""
        current = dns.qd

        if current is None:
            return []

        if isinstance(current, (list, tuple)):
            records = current
        else:
            records = []
            while isinstance(current, DNSQR):
                records.append(current)
                current = current.payload

        return [
            {
                "name": DNSDetector._domain(record.qname),
                "type": DNSDetector._record_type(record.qtype),
            }
            for record in records
            if isinstance(record, DNSQR)
        ]

    @staticmethod
    def _packet_answers(dns):
        """Extract DNS answers from Scapy list or chained fields."""
        current = dns.an

        if current is None:
            return []

        if isinstance(current, (list, tuple)):
            records = current
        else:
            records = []
            while isinstance(current, DNSRR):
                records.append(current)
                current = current.payload

        return [
            {
                "name": DNSDetector._domain(record.rrname),
                "type": int(record.type),
                "data": str(record.rdata),
            }
            for record in records
            if isinstance(record, DNSRR)
        ]

    def _query_key(self, record):
        return (
            int(record.get("transaction_id", 0)),
            record.get("src_ip"),
            record.get("dst_ip"),
            self._domain(record.get("domain", "")),
            self._record_type(record.get("record_type", "A")),
        )

    def _response_query_key(self, record):
        return (
            int(record.get("transaction_id", 0)),
            record.get("dst_ip"),
            record.get("src_ip"),
            self._domain(record.get("domain", "")),
            self._record_type(record.get("record_type", "A")),
        )

    def _cleanup_expired_queries(self, now):
        """Expire old queries while retaining markers for late responses."""
        expired_keys = [
            key
            for key, query in self.pending_queries.items()
            if now - query["timestamp"] > self.QUERY_TIMEOUT
        ]

        for key in expired_keys:
            self._expired_queries[key] = self.pending_queries.pop(key)

        stale_keys = [
            key
            for key, query in self._expired_queries.items()
            if now - query["timestamp"] > self.CONFLICT_WINDOW
        ]

        for key in stale_keys:
            del self._expired_queries[key]

        return len(expired_keys)

    def cleanup_expired_queries(self, now=None):
        """Public helper for removing expired pending queries."""
        if now is None:
            now = time.time()
        return self._cleanup_expired_queries(float(now))

    def _find_expired_query(self, response):
        key = self._response_query_key(response)
        return self._expired_queries.pop(key, None) is not None

    def process_record(self, record):
        """Process normalized DNS metadata and return a list of alerts."""
        now = float(record.get("timestamp", time.time()))
        self._cleanup_expired_queries(now)

        domain = self._domain(record.get("domain", ""))
        record_type = self._record_type(record.get("record_type", "A"))
        normalized_record = {
            **record,
            "domain": domain,
            "record_type": record_type,
        }

        if not record.get("is_response", False):
            key = self._query_key(normalized_record)
            self.pending_queries[key] = {
                "timestamp": now,
                "record": dict(record),
            }
            return []

        alerts = []
        response_key = self._response_query_key(normalized_record)
        query = self.pending_queries.pop(response_key, None)

        if query is None:
            if self._find_expired_query(normalized_record):
                alerts.append({
                    "alert_type": "UNSOLICITED_DNS_RESPONSE",
                    "severity": "HIGH",
                    "domain": domain,
                    "reason": "DNS response arrived after its query timed out.",
                })
            elif self.settings.get("detect_unsolicited_responses", True):
                alerts.append({
                    "alert_type": "UNSOLICITED_DNS_RESPONSE",
                    "severity": "HIGH",
                    "domain": domain,
                    "reason": "No matching DNS query was recorded.",
                })

        answers = set()
        for answer in record.get("answers", []):
            normalized = self._normalize_ipv4(answer)
            answers.add(normalized if normalized else str(answer))

        server_ip = record.get("src_ip")
        if (
            self.settings.get("detect_unauthorized_servers", False)
            and self.allowed_dns_servers
            and server_ip not in self.allowed_dns_servers
        ):
            alerts.append({
                "alert_type": "UNAUTHORIZED_DNS_SERVER",
                "severity": "HIGH",
                "domain": domain,
                "dns_server": server_ip,
                "reason": "Response came from a non-approved DNS server.",
            })

        expected = self.expected_dns_answers.get(domain)
        if (
            record_type == "A"
            and expected is not None
            and self.settings.get("detect_unexpected_answers", True)
        ):
            unexpected = answers - expected
            if unexpected:
                alerts.append({
                    "alert_type": "UNEXPECTED_DNS_ANSWER",
                    "severity": "HIGH",
                    "domain": domain,
                    "observed_ips": sorted(answers),
                    "expected_ips": sorted(expected),
                    "reason": "Answer differs from the configured DNS baseline.",
                })

        history_key = (domain, record_type)
        previous = self.recent_answers.get(history_key)
        window = float(
            self.settings.get(
                "conflict_window_seconds", self.CONFLICT_WINDOW
            )
        )

        if (
            record_type == "A"
            and previous is not None
            and 0 <= now - previous["timestamp"] <= window
            and answers != previous["answers"]
            and self.settings.get("detect_conflicting_answers", True)
        ):
            alerts.append({
                "alert_type": "CONFLICTING_DNS_ANSWERS",
                "severity": "MEDIUM",
                "domain": domain,
                "previous_answers": sorted(previous["answers"]),
                "current_answers": sorted(answers),
                "reason": (
                    "Different DNS answers were observed within the time window."
                ),
            })

        self.recent_answers[history_key] = {
            "timestamp": now,
            "answers": answers,
        }

        return alerts

    def process_packet(self, packet):
        """Process a Scapy DNS packet and return a status dictionary."""
        if not packet.haslayer(DNS):
            return {
                "status": "ignored",
                "reason": "Packet contains no DNS layer",
            }

        dns = packet[DNS]
        questions = self._packet_questions(dns)
        packet_answers = self._packet_answers(dns)

        if questions:
            domain = questions[0]["name"]
            record_type = questions[0]["type"]
        elif dns.qr and packet_answers:
            domain = packet_answers[0]["name"]
            record_type = self._record_type(packet_answers[0]["type"])
        else:
            return {
                "status": "ignored",
                "reason": "DNS question is unavailable",
            }

        if not dns.qr:
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None
            timestamp = (
                float(packet.time) if hasattr(packet, "time") else time.time()
            )

            self.process_record({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "transaction_id": int(dns.id),
                "domain": domain,
                "record_type": record_type,
                "is_response": False,
                "answers": [],
            })
            return {
                "status": "observed",
                "domain": domain,
                "reason": "DNS query recorded",
            }

        ipv4_answers = {
            normalized
            for answer in packet_answers
            if answer["type"] == 1
            if (
                normalized := self._normalize_ipv4(answer["data"])
            ) is not None
        }

        if not ipv4_answers:
            return {
                "status": "ignored",
                "reason": "No valid IPv4 A records found",
                "domain": domain,
            }

        ledger_key = (domain, record_type)
        known_answers = self.ledger.setdefault(ledger_key, set())
        alerts = []

        # Packet-level detection compares with the observed ledger.
        # Configured baselines are checked separately by process_record().
        new_answers = ipv4_answers - known_answers
        if known_answers and new_answers:
            alerts.extend({
                "answer_ip": ip,
                "known_ips": sorted(known_answers),
                "reason": "DNS answer differs from previously observed answer",
            } for ip in sorted(new_answers))

        known_answers.update(ipv4_answers)

        if alerts:
            return {
                "status": "alert",
                "domain": domain,
                "alerts": alerts,
            }

        return {
            "status": "observed",
            "domain": domain,
            "reason": "DNS answer matches or establishes the observed baseline",
        }
