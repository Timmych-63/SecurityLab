"""Reviewed, synthetic fixture only. No AI-generated Python is run on the host."""
import hashlib

VULNERABLE = '''RECORDS = {"one": {"owner": "alice", "value": "synthetic-A"},
           "two": {"owner": "bob", "value": "synthetic-B"}}

def read_record(user, record_id):
    if user is None:
        return 401, None
    record = RECORDS.get(record_id)
    if record is None:
        return 404, None
    return 200, record["value"]
'''
FIXED = VULNERABLE.replace('    return 200, record["value"]',
    '    if record["owner"] != user:\n        return 403, None\n    return 200, record["value"]')
# This exact suite is used before and after the patch, and kept outside the repo.
SUITE = '''import importlib.util, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("fixture_service", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks = {
 "owner_read": m.read_record("alice", "one") == (200, "synthetic-A"),
 "other_owner_read": m.read_record("bob", "two") == (200, "synthetic-B"),
 "anonymous_rejected": m.read_record(None, "one") == (401, None),
 "missing_record": m.read_record("alice", "missing") == (404, None),
 "cross_user_denied": m.read_record("alice", "two") == (403, None),
 "reverse_cross_user_denied": m.read_record("bob", "one") == (403, None),
 "unknown_user_denied": m.read_record("mallory", "one") == (403, None),
}
print(json.dumps({"checks": checks, "observed": list(m.read_record("alice", "two"))}))
sys.exit(0 if all(checks.values()) else 1)
'''
REGRESSION = '''import unittest
from service import read_record
class AccessTest(unittest.TestCase):
    def test_other_owner_denied(self):
        self.assertEqual(read_record("alice", "two"), (403, None))
    def test_owner_allowed(self):
        self.assertEqual(read_record("bob", "two"), (200, "synthetic-B"))
if __name__ == "__main__":
    unittest.main()
'''

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()
