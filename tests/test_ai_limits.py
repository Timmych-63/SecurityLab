import unittest
from securitylab.hermes_adapter import AIProcessLimits
from securitylab.policy import Limits, PolicyError

class AILimitsTests(unittest.TestCase):
    def test_longer_deadline_is_ai_only(self):
        self.assertEqual(AIProcessLimits().timeout,1200)
        with self.assertRaises(PolicyError): Limits(timeout=1200)
    def test_bounded_timeout_and_output(self):
        for n in (0,1201,True,1200.0):
            with self.subTest(n=n),self.assertRaises(PolicyError): AIProcessLimits(timeout=n)
        with self.assertRaises(PolicyError): AIProcessLimits(output_bytes=1048577)
