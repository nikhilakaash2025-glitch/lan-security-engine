
import ipaddress

from scapy.all import DNS, DNSQR


class DNSDetector:
    """Track DNS answers and flag unexpected changes."""

    def __init__(self, trusted_records=None):
        # Map (domain, record type) to known answer IP addresses.
        self.ledger = {}
        self.trusted_records = trusted_records or {}

    def process_packet(self, packet):
        """Inspect a DNS response and report suspicious A records."""
        if not packet.haslayer(DNS):
            return {
                "status": "ignored",
                "reason": "Packet contains no DNS layer",
            }

        dns = packet[DNS]

        if dns.qr != 1 or dns.ancount == 0:
            return {
                "status": "ignored",
                "reason": "Not a DNS response with answers",
            }

        if not packet.haslayer(DNSQR):
            return {
                "status": "ignored",
                "reason": "DNS query name is unavailable",
            }

        query_name = packet[DNSQR].qname.decode(
            "utf-8", errors="replace"
        ).rstrip(".").lower()

        if not query_name:
            return {
                "status": "ignored",
                "reason": "DNS query name is unavailable",
            }

        alerts = []
        answer_count = 0

        for answer in dns.an:
            if answer.type != 1:
                continue

            try:
                answer_ip = str(ipaddress.IPv4Address(answer.rdata))
            except (ipaddress.AddressValueError, TypeError):
                continue

            answer_count += 1
            key = (query_name, "A")

            known_ips = self.ledger.get(key, set())
            trusted_ips = self.trusted_records.get(key)

            if trusted_ips is not None:
                normalized_trusted = {
                    str(ipaddress.IPv4Address(ip))
                    for ip in trusted_ips
                }

                if answer_ip not in normalized_trusted:
                    alerts.append({
                        "answer_ip": answer_ip,
                        "reason": "Answer conflicts with trusted DNS records",
                    })
                    continue

            if not known_ips:
                self.ledger.setdefault(key, set()).add(answer_ip)
            elif answer_ip not in known_ips:
                alerts.append({
                    "answer_ip": answer_ip,
                    "known_ips": sorted(known_ips),
                    "reason": (
                        "DNS answer differs from previously observed answer"
                    ),
                })

        if answer_count == 0:
            return {
                "status": "ignored",
                "reason": "No valid IPv4 A records found",
                "domain": query_name,
            }

        if alerts:
            return {
                "status": "alert",
                "domain": query_name,
                "alerts": alerts,
            }

        return {
            "status": "observed",
            "domain": query_name,
            "reason": (
                "DNS answer matches or establishes the observed baseline"
            ),
        }
