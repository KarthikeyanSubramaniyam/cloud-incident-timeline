import unittest
from analyzer import analyze

class Cases(unittest.TestCase):
    def test_security_behavior(self):
        result = analyze({"Records":[{"eventID":"a","eventTime":"2026-10-03T12:00:00+01:00"},{"eventID":"b","eventTime":"2026-10-03T10:30:00Z"},{"eventID":"a","eventTime":"2026-10-03T12:00:00+01:00"}]})
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["resource"], "b")

if __name__ == "__main__":
    unittest.main()

