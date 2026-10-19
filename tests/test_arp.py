
import unittest

from arp_detector import ArpDetector, normalize_ip, normalize_mac


class TestArpDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ArpDetector()

    def test_first_mapping_is_learned(self):
        result = self.detector.process_mapping(
            "192.168.1.10", "AA:BB:CC:DD:EE:10"
        )

        self.assertEqual(result["status"], "learned")
        self.assertEqual(
            self.detector.get_ledger()["192.168.1.10"],
            "aa:bb:cc:dd:ee:10",
        )

    def test_same_mapping_is_unchanged(self):
        self.detector.process_mapping(
            "192.168.1.10", "aa:bb:cc:dd:ee:10"
        )

        result = self.detector.process_mapping(
            "192.168.1.10", "AA:BB:CC:DD:EE:10"
        )

        self.assertEqual(result["status"], "unchanged")

    def test_changed_mapping_generates_alert(self):
        self.detector.process_mapping(
            "192.168.1.10", "aa:bb:cc:dd:ee:10"
        )

        result = self.detector.process_mapping(
            "192.168.1.10", "aa:bb:cc:dd:ee:99"
        )

        self.assertEqual(result["status"], "alert")
        self.assertEqual(result["old_mac"], "aa:bb:cc:dd:ee:10")
        self.assertEqual(result["new_mac"], "aa:bb:cc:dd:ee:99")

        # By default, the original mapping remains in the ledger.
        self.assertEqual(
            self.detector.get_ledger()["192.168.1.10"],
            "aa:bb:cc:dd:ee:10",
        )

    def test_trusted_mapping_conflict_generates_alert(self):
        detector = ArpDetector(
            trusted_mappings={
                "192.168.1.1": "aa:bb:cc:dd:ee:01"
            }
        )

        result = detector.process_mapping(
            "192.168.1.1", "aa:bb:cc:dd:ee:99"
        )

        self.assertEqual(result["status"], "alert")
        self.assertIn("trusted", result["reason"].lower())

    def test_update_on_change_can_be_enabled(self):
        detector = ArpDetector(update_on_change=True)

        detector.process_mapping(
            "192.168.1.10", "aa:bb:cc:dd:ee:10"
        )

        result = detector.process_mapping(
            "192.168.1.10", "aa:bb:cc:dd:ee:99"
        )

        self.assertEqual(result["status"], "alert")
        self.assertEqual(
            detector.get_ledger()["192.168.1.10"],
            "aa:bb:cc:dd:ee:99",
        )

    def test_invalid_mac_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_mac("not-a-mac")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ip("999.999.999.999")


if __name__ == "__main__":
    unittest.main()
