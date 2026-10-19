import unittest

from risk_engine import classify_risk, score_event


class TestRiskEngine(unittest.TestCase):

    def test_risk_levels(self):
        self.assertEqual(classify_risk(0), "LOW")
        self.assertEqual(classify_risk(30), "MEDIUM")
        self.assertEqual(classify_risk(69), "MEDIUM")
        self.assertEqual(classify_risk(70), "HIGH")
        self.assertEqual(classify_risk(100), "HIGH")

    def test_normal_arp_result(self):
        result = score_event({
            "status": "unchanged",
            "ip": "192.168.1.10",
        })
        self.assertEqual(result["risk_score"], 0)
        self.assertFalse(result["dry_run_isolation"])

    def test_arp_alert(self):
        result = score_event({
            "status": "alert",
            "ip": "192.168.1.10",
            "old_mac": "aa:bb:cc:dd:ee:ff",
            "new_mac": "11:22:33:44:55:66",
        })
        self.assertEqual(result["event_type"], "ARP")
        self.assertEqual(result["risk_score"], 45)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_dns_alert(self):
        result = score_event({
            "status": "alert",
            "domain": "example.test",
            "alerts": [{"reason": "Unexpected answer"}],
        })
        self.assertEqual(result["event_type"], "DNS")
        self.assertEqual(result["risk_score"], 52)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_high_confidence_dns_alert(self):
        result = score_event({
            "status": "alert",
            "event_type": "DNS",
            "confidence": 1.0,
        })
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertTrue(result["dry_run_isolation"])

    def test_invalid_confidence(self):
        with self.assertRaises(ValueError):
            score_event({
                "status": "alert",
                "event_type": "DNS",
                "confidence": 1.5,
            })


if __name__ == "__main__":
    unittest.main()
