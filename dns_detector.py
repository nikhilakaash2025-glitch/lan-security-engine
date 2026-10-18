import json
from pathlib import Path


class DNSDetector:
    """
    Detects suspicious DNS activity using configurable rules.
    """

    def __init__(self, config_path="dns_config.json"):

        # Load configuration from JSON file
        config_file = Path(config_path)

        with config_file.open("r", encoding="utf-8") as file:
            self.config = json.load(file)

        # Read approved DNS servers
        self.allowed_dns_servers = set(
            self.config["allowed_dns_servers"]
        )

        # Read expected DNS answers
        self.expected_dns_answers = self.config[
            "expected_dns_answers"
        ]

        # Read detection settings
        self.settings = self.config[
            "detection_settings"
        ]

        # Store recent DNS queries
        self.pending_queries = {}

        # Store recent DNS responses
        self.recent_responses = {}

        print("[INFO] DNS Detector initialized successfully.")


    def detect_unexpected_answer(self, record):
        """
        Detect DNS answers that differ from configured expected IPs.

        Returns:
            list: Anomaly alerts
        """

        alerts = []

        if not self.settings.get(
            "detect_unexpected_answers", False
        ):
            return alerts

        if not record["is_response"]:
            return alerts

        if record["record_type"] != "A":
            return alerts

        domain = record["domain"].lower().rstrip(".")
        received_ips = set(record["answers"])

        expected_ips = self.expected_dns_answers.get(domain)

        # Only check domains with an explicitly configured baseline
        if expected_ips is None:
            return alerts

        expected_ips = set(expected_ips)

        unexpected_ips = received_ips - expected_ips

        if unexpected_ips:
            alert = {
                "alert_type": "UNEXPECTED_DNS_ANSWER",
                "severity": "HIGH",
                "domain": domain,
                "description": (
                    "DNS response contains an IP address "
                    "outside the configured expected answers."
                ),
                "observed_ips": sorted(received_ips),
                "expected_ips": sorted(expected_ips),
                "timestamp": record["timestamp"]
            }

            alerts.append(alert)

        return alerts
    def detect_unauthorized_server(self, record):
        """Detect responses from DNS servers outside the approved list."""
        alerts = []

        if not self.settings.get("detect_unauthorized_servers", False):
            return alerts

        if not record["is_response"]:
            return alerts

        dns_server = record["src_ip"]

        if dns_server not in self.allowed_dns_servers:
            alerts.append({
                "alert_type": "UNAUTHORIZED_DNS_SERVER",
                "severity": "HIGH",
                "domain": record["domain"],
                "description": "DNS response from an unauthorized server.",
                "dns_server": dns_server,
                "timestamp": record["timestamp"]
            })

        return alerts


    def detect_conflicting_answers(self, record):
        """Detect conflicting DNS answers within a time window."""

        alerts = []

        if not self.settings.get("detect_conflicting_answers", False):
            return alerts

        if not record["is_response"]:
            return alerts

        if record["record_type"] != "A":
            return alerts

        domain = record["domain"].lower().rstrip(".")
        current_answers = set(record["answers"])
        timestamp = record["timestamp"]

        window = self.settings.get("conflict_window_seconds", 30)

        previous = self.recent_responses.get(domain)

        if previous is not None:
            previous_answers = set(previous["answers"])
            previous_time = previous["timestamp"]

            time_difference = timestamp - previous_time

            if 0 <= time_difference <= window:
                if current_answers != previous_answers:
                    alerts.append({
                        "alert_type": "CONFLICTING_DNS_ANSWERS",
                        "severity": "MEDIUM",
                        "domain": domain,
                        "description": (
                            "Different DNS answers observed "
                            "within the configured time window."
                        ),
                        "previous_answers": sorted(previous_answers),
                        "current_answers": sorted(current_answers),
                        "timestamp": timestamp
                    })

        self.recent_responses[domain] = {
            "answers": sorted(current_answers),
            "timestamp": timestamp
        }

        return alerts


    def detect_unsolicited_response(self, record):
        """Detect DNS responses without a matching recent query."""

        alerts = []

        if not self.settings.get("detect_unsolicited_responses", False):
            return alerts

        domain = record["domain"].lower().rstrip(".")
        transaction_id = record["transaction_id"]
        timestamp = record["timestamp"]

        # Remove expired pending queries
        timeout = self.settings.get("query_timeout_seconds", 5)

        expired_keys = [
            key
            for key, query_time in self.pending_queries.items()
            if timestamp - query_time > timeout
        ]

        for key in expired_keys:
            del self.pending_queries[key]

        if not record["is_response"]:

            query_key = (
                transaction_id,
                domain,
                record["src_ip"],
                record["dst_ip"]
            )

            self.pending_queries[query_key] = timestamp
            return alerts

        response_key = (
            transaction_id,
            domain,
            record["dst_ip"],
            record["src_ip"]
        )

        query_time = self.pending_queries.pop(response_key, None)

        timeout = self.settings.get("query_timeout_seconds", 5)

        if (
            query_time is None
            or not 0 <= timestamp - query_time <= timeout
        ):
            alerts.append({
                "alert_type": "UNSOLICITED_DNS_RESPONSE",
                "severity": "HIGH",
                "domain": domain,
                "description": (
                    "DNS response received without a "
                    "matching recent DNS query."
                ),
                "dns_server": record["src_ip"],
                "transaction_id": transaction_id,
                "timestamp": timestamp
            })

        return alerts

    def process_record(self, record):
        """
        Process a normalized DNS record.

        Input:
            record (dict): DNS query or response

        Output:
            list: Anomaly alerts
        """

        alerts = []

        if record["is_response"]:

            print(
                f"[DNS RESPONSE] {record['domain']} "
                f"-> {record['answers']}"
            )

            alerts.extend(
                self.detect_unexpected_answer(record)
            )
            alerts.extend(
                self.detect_unauthorized_server(record)
            )
            alerts.extend(
                self.detect_conflicting_answers(record)
            )

            alerts.extend(
                self.detect_unsolicited_response(record)
            )

        else:
            print(
                f"[DNS QUERY] {record['domain']}"
            )

            self.detect_unsolicited_response(record)

        return alerts

        


if __name__ == "__main__":

    detector = DNSDetector()

    # Synthetic DNS query for testing
    sample_query = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "transaction_id": 1234,
        "domain": "example.com",
        "record_type": "A",
        "is_response": False,
        "answers": []
    }

    result = detector.process_record(sample_query)

    print("Alerts:", result)
