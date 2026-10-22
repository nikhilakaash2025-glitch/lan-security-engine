import unittest

from enforcement_adapter import enforce_response


class TestEnforcementAdapter(unittest.TestCase):

    def test_block_recommendation_is_simulated(self):
        result = enforce_response({
            "action": "BLOCK_RECOMMENDED"
        })

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "SIMULATED_ONLY")
        self.assertFalse(result["blocked"])

    def test_monitor_action_is_accepted(self):
        result = enforce_response({"action": "MONITOR"})

        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "MONITOR")
        self.assertFalse(result["blocked"])

    def test_investigate_action_is_accepted(self):
        result = enforce_response({"action": "INVESTIGATE"})

        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "INVESTIGATE")

    def test_unknown_action_is_rejected(self):
        result = enforce_response({"action": "DELETE_EVERYTHING"})

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "REJECTED")
        self.assertFalse(result["blocked"])

    def test_missing_action_is_rejected(self):
        result = enforce_response({})

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
