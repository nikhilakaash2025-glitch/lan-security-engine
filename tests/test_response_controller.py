import unittest

from response_controller import (
    recommend_response,
    report_enforcement_test,
)


class TestResponseController(unittest.TestCase):

    def test_low_risk_recommends_monitoring(self):
        result = recommend_response({
            "risk_score": 0,
            "risk_level": "LOW",
        })

        self.assertEqual(result["action"], "MONITOR")
        self.assertEqual(result["mode"], "DRY_RUN")
        self.assertFalse(result["blocked"])

    def test_medium_risk_recommends_investigation(self):
        result = recommend_response({
            "risk_score": 45,
            "risk_level": "MEDIUM",
        })

        self.assertEqual(result["action"], "INVESTIGATE")
        self.assertFalse(result["blocked"])

    def test_high_risk_recommends_blocking(self):
        result = recommend_response({
            "risk_score": 75,
            "risk_level": "HIGH",
        })

        self.assertEqual(result["action"], "BLOCK_RECOMMENDED")
        self.assertEqual(
            result["enforcement_status"],
            "NOT_ATTEMPTED",
        )
        self.assertFalse(result["blocked"])

    def test_enforcement_test_is_simulation_only(self):
        result = report_enforcement_test({
            "risk_score": 75,
            "risk_level": "HIGH",
        })

        self.assertEqual(result["mode"], "TEST_SIMULATION")
        self.assertEqual(
            result["enforcement_status"],
            "SIMULATED_ONLY",
        )
        self.assertFalse(result["blocked"])


if __name__ == "__main__":
    unittest.main()
