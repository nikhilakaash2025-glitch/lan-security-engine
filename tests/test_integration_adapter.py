import csv
import tempfile
import unittest
from pathlib import Path

from integration_adapter import process_result


class TestIntegrationAdapter(unittest.TestCase):
    def test_arp_alert_is_scored_and_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "results.csv"
            result = {
                "status": "alert",
                "ip": "192.0.2.10",
                "old_mac": "00:11:22:33:44:55",
                "new_mac": "00:11:22:33:44:66",
                "reason": "IP address is now associated with a different MAC",
            }

            processed = process_result("ARP", result, log_path)

            self.assertEqual(len(processed), 1)
            self.assertEqual(processed[0]["risk"]["event_type"], "ARP")
            self.assertGreater(processed[0]["risk"]["risk_score"], 0)
            self.assertFalse(
                any("isolation_executed" in item for item in processed)
            )

            with log_path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_ip"], "192.0.2.10")

    def test_multiple_dns_alerts_are_logged_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "results.csv"
            result = {
                "status": "alert",
                "domain": "example.test",
                "alerts": [
                    {
                        "answer_ip": "198.51.100.10",
                        "reason": "Unexpected DNS answer",
                    },
                    {
                        "answer_ip": "198.51.100.11",
                        "reason": "Conflicting DNS answer",
                    },
                ],
            }

            processed = process_result("DNS", result, log_path)

            self.assertEqual(len(processed), 2)
            self.assertTrue(
                all(item["risk"]["event_type"] == "DNS" for item in processed)
            )
            self.assertTrue(
                all(item["risk"]["risk_score"] > 0 for item in processed)
            )

            with log_path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 2)
            self.assertEqual(
                [item["event"]["reason"] for item in processed],
                ["Unexpected DNS answer", "Conflicting DNS answer"],
            )
            self.assertEqual(
                [item["event"]["domain"] for item in processed],
                ["example.test", "example.test"],
            )

    def test_non_alert_result_has_zero_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "results.csv"

            processed = process_result(
                "ARP",
                {
                    "status": "learned",
                    "ip": "192.0.2.20",
                    "reason": "First mapping observed",
                },
                log_path,
            )

            self.assertEqual(len(processed), 1)
            self.assertEqual(processed[0]["risk"]["risk_score"], 0)
            self.assertFalse(processed[0]["risk"]["dry_run_isolation"])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(ValueError):
            process_result("HTTP", {"status": "alert"}, "unused.csv")


if __name__ == "__main__":
    unittest.main()
