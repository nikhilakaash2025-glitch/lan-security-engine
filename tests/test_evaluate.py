import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evaluate

FIELDS = [
    "timestamp", "event_type", "status", "risk_score",
    "risk_level", "source_ip", "domain", "reason",
    "dry_run_isolation",
]


class TestEvaluation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.csv_path = self.root / "results.csv"
        self.plot_dir = self.root / "plots"
        self.p1 = patch.object(evaluate, "CSV_PATH", self.csv_path)
        self.p2 = patch.object(evaluate, "PLOT_DIR", self.plot_dir)
        self.p1.start()
        self.p2.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.tmp.cleanup()

    def write_csv(self, rows):
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def row(self, timestamp, score="45", level="MEDIUM"):
        return {
            "timestamp": timestamp,
            "event_type": "ARP",
            "status": "alert",
            "risk_score": score,
            "risk_level": level,
            "source_ip": "192.0.2.10",
            "domain": "",
            "reason": "simulated test event",
            "dry_run_isolation": "False",
        }

    def test_missing_csv(self):
        with self.assertRaisesRegex(SystemExit, "CSV file not found"):
            evaluate.main()

    def test_empty_csv(self):
        self.write_csv([])
        with self.assertRaisesRegex(SystemExit, "CSV contains no results"):
            evaluate.main()

    def test_invalid_scores(self):
        self.write_csv([self.row("invalid-time", "invalid")])
        with self.assertRaisesRegex(SystemExit, "No valid risk scores"):
            evaluate.main()

    def test_valid_events_create_both_plots(self):
        self.write_csv([
            self.row("2026-10-19T10:00:00+00:00"),
            self.row("2026-10-19T10:05:00+00:00", "70", "HIGH"),
        ])
        evaluate.main()
        self.assertTrue((self.plot_dir / "risk_distribution.png").is_file())
        self.assertTrue((self.plot_dir / "detection_timeline.png").is_file())

    def test_invalid_timestamp_still_creates_distribution(self):
        self.write_csv([self.row("invalid-time")])
        evaluate.main()
        self.assertTrue((self.plot_dir / "risk_distribution.png").is_file())
        self.assertFalse((self.plot_dir / "detection_timeline.png").exists())


if __name__ == "__main__":
    unittest.main()
