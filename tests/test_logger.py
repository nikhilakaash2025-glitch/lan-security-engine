import csv
import tempfile
import unittest
from pathlib import Path

from logger import CSV_FIELDS, log_result


class TestCSVLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.csv_path = Path(self.temp_dir.name) / "nested" / "results.csv"

    def tearDown(self):
        self.temp_dir.cleanup()

    def read_rows(self):
        with self.csv_path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_creates_parent_directory_and_header(self):
        log_result(
            {"event_type": "ARP", "status": "alert", "ip": "192.0.2.10"},
            {"event_type": "ARP", "risk_score": 45,
             "risk_level": "MEDIUM", "reason": "Simulated alert"},
            self.csv_path,
        )

        with self.csv_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.assertEqual(reader.fieldnames, CSV_FIELDS)
            rows = list(reader)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_ip"], "192.0.2.10")
        self.assertEqual(rows[0]["risk_score"], "45")

    def test_appends_multiple_events_without_duplicate_headers(self):
        log_result(
            {"event_type": "ARP", "status": "alert"},
            {"event_type": "ARP", "risk_score": 45,
             "risk_level": "MEDIUM", "reason": "First event"},
            self.csv_path,
        )
        log_result(
            {"event_type": "DNS", "status": "alert",
             "domain": "example.test"},
            {"event_type": "DNS", "risk_score": 70,
             "risk_level": "HIGH", "reason": "Second event",
             "dry_run_isolation": True},
            self.csv_path,
        )

        rows = self.read_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["event_type"], "ARP")
        self.assertEqual(rows[1]["event_type"], "DNS")
        self.assertEqual(rows[1]["domain"], "example.test")
        self.assertEqual(rows[1]["dry_run_isolation"], "True")

        with self.csv_path.open(encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(sum(line.startswith("timestamp,") for line in lines), 1)

    def test_preserves_supplied_timestamp(self):
        timestamp = "2026-10-19T12:00:00+00:00"
        log_result(
            {"timestamp": timestamp, "status": "observed"},
            {"event_type": "ARP", "risk_score": 0,
             "risk_level": "LOW", "reason": "No alert"},
            self.csv_path,
        )

        self.assertEqual(self.read_rows()[0]["timestamp"], timestamp)

    def test_handles_empty_event_fields(self):
        log_result(
            {},
            {"event_type": "UNKNOWN", "risk_score": 0,
             "risk_level": "LOW", "reason": "No alert"},
            self.csv_path,
        )

        row = self.read_rows()[0]
        self.assertEqual(row["source_ip"], "")
        self.assertEqual(row["domain"], "")
        self.assertNotEqual(row["timestamp"], "")


if __name__ == "__main__":
    unittest.main()
