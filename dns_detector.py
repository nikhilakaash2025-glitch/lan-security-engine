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

    def process_record(self, record):
        """
        Process a normalized DNS query or response.

        Input:
            record (dict): DNS record

        Output:
            list: Detected anomaly alerts
        """

        alerts = []

        if record["is_response"]:
            print(
                f"[DNS RESPONSE] {record['domain']} "
                f"-> {record['answers']}"
            )
        else:
            print(
                f"[DNS QUERY] {record['domain']}"
            )

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
