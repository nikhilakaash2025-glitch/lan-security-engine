import unittest
import sys
from pathlib import Path

# Allow importing dns_detector.py from the project directory
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from dns_detector import DNSDetector


class TestDNSDetector(unittest.TestCase):
    def setUp(self):
        config_path = (
            Path(__file__).resolve().parents[1]
            / "dns_config.json"
        )
        self.detector = DNSDetector(config_path)


    def send_matching_query(self, response):
        """Send the query corresponding to a DNS response."""
        query = {
            **response,
            "timestamp": response["timestamp"] - 1,
            "src_ip": response["dst_ip"],
            "dst_ip": response["src_ip"],
            "is_response": False,
            "answers": []
        }
        self.detector.process_record(query)

    def test_expected_dns_answer(self):

        record = {
            "timestamp": 1000.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 1234,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        self.send_matching_query(record)
        alerts = self.detector.process_record(record)

        self.assertEqual(alerts, [])

    def test_unexpected_dns_answer(self):

        record = {
            "timestamp": 1000.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 1234,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["192.0.2.50"]
        }

        self.send_matching_query(record)
        alerts = self.detector.process_record(record)

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["alert_type"],
            "UNEXPECTED_DNS_ANSWER"
        )



    def test_authorized_dns_server(self):
        """An approved DNS server should not trigger an alert."""
        record = {
            "timestamp": 1001.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 1235,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        self.send_matching_query(record)
        alerts = self.detector.process_record(record)
        self.assertEqual(alerts, [])

    def test_unauthorized_dns_server(self):
        """An unapproved DNS server should trigger an alert."""
        record = {
            "timestamp": 1002.0,
            "src_ip": "192.0.2.53",
            "dst_ip": "192.168.1.10",
            "transaction_id": 1236,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        self.send_matching_query(record)
        alerts = self.detector.process_record(record)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "UNAUTHORIZED_DNS_SERVER"
        )


    def test_conflicting_dns_answers(self):
        """Different answers within 30 seconds trigger a conflict."""

        record1 = {
            "timestamp": 1000.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 2001,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        record2 = {
            **record1,
            "timestamp": 1010.0,
            "transaction_id": 2002,
            "answers": ["192.0.2.50"]
        }

        self.send_matching_query(record1)
        self.detector.process_record(record1)
        self.send_matching_query(record2)
        alerts = self.detector.process_record(record2)

        alert_types = [a["alert_type"] for a in alerts]

        self.assertIn(
            "CONFLICTING_DNS_ANSWERS",
            alert_types
        )

    def test_identical_dns_answers(self):
        """Identical answers should not trigger a conflict."""

        record = {
            "timestamp": 1000.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 2003,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        self.send_matching_query(record)
        self.detector.process_record(record)

        record2 = {
            **record,
            "timestamp": 1010.0,
            "transaction_id": 2004
        }

        self.send_matching_query(record2)
        alerts = self.detector.process_record(record2)

        alert_types = [a["alert_type"] for a in alerts]

        self.assertNotIn(
            "CONFLICTING_DNS_ANSWERS",
            alert_types
        )

    def test_conflict_outside_time_window(self):
        """Different answers after 30 seconds should not conflict."""

        record1 = {
            "timestamp": 1000.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 2005,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        record2 = {
            **record1,
            "timestamp": 1040.0,
            "transaction_id": 2006,
            "answers": ["192.0.2.50"]
        }

        self.send_matching_query(record1)
        self.detector.process_record(record1)
        self.send_matching_query(record2)
        alerts = self.detector.process_record(record2)

        alert_types = [a["alert_type"] for a in alerts]

        self.assertNotIn(
            "CONFLICTING_DNS_ANSWERS",
            alert_types
        )


    def test_matching_dns_query_response(self):
        """A matching query and response should not be unsolicited."""
        response = {
            "timestamp": 1001.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 3001,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        self.send_matching_query(response)
        alerts = self.detector.process_record(response)

        alert_types = [a["alert_type"] for a in alerts]

        self.assertNotIn(
            "UNSOLICITED_DNS_RESPONSE",
            alert_types
        )

    def test_unsolicited_dns_response(self):
        """A response without a query should trigger an alert."""
        response = {
            "timestamp": 1001.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 3002,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        alerts = self.detector.process_record(response)
        alert_types = [a["alert_type"] for a in alerts]

        self.assertIn(
            "UNSOLICITED_DNS_RESPONSE",
            alert_types
        )

    def test_dns_response_after_timeout(self):
        """A response arriving after 5 seconds should trigger an alert."""
        response = {
            "timestamp": 1010.0,
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "transaction_id": 3003,
            "domain": "example.com",
            "record_type": "A",
            "is_response": True,
            "answers": ["93.184.215.14"]
        }

        query = {
            **response,
            "timestamp": 1000.0,
            "src_ip": response["dst_ip"],
            "dst_ip": response["src_ip"],
            "is_response": False,
            "answers": []
        }

        self.detector.process_record(query)
        alerts = self.detector.process_record(response)

        alert_types = [a["alert_type"] for a in alerts]

        self.assertIn(
            "UNSOLICITED_DNS_RESPONSE",
            alert_types
        )


    def test_expired_query_cleanup(self):
        """Expired pending DNS queries should be removed."""

        query1 = {
            "timestamp": 1000.0,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "transaction_id": 4001,
            "domain": "example.com",
            "record_type": "A",
            "is_response": False,
            "answers": []
        }

        query2 = {
            **query1,
            "timestamp": 1010.0,
            "transaction_id": 4002
        }

        # Store the first query
        self.detector.process_record(query1)

        self.assertEqual(
            len(self.detector.pending_queries), 1
        )

        # Process a new query after the 5-second timeout
        self.detector.process_record(query2)

        # Old query removed; new query remains
        self.assertEqual(
            len(self.detector.pending_queries), 1
        )

        remaining_key = next(
            iter(self.detector.pending_queries)
        )

        self.assertEqual(remaining_key[0], 4002)

if __name__ == "__main__":
    unittest.main()
