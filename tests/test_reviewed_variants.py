"""Regression for the user's rejected owner-variable proposal."""
import unittest
from securitylab.ai_contract import REVIEWED_FIXES, reviewed_variant, validate_proposal
from securitylab.policy import PolicyError


class ReviewedVariantTests(unittest.TestCase):
    def test_variants_and_expected_behavior(self):
        # Execute developer-owned constants only, never external/model input.
        for name, source in REVIEWED_FIXES.items():
            with self.subTest(name=name):
                validate_proposal('blue', {'file': 'service.py', 'content': source})
                self.assertEqual(reviewed_variant(source), name)
                namespace = {}
                exec(compile(source, '<reviewed-template>', 'exec'), namespace)
                for user in [None, 'alice', 'bob', 'attacker', '']:
                    for rid in ['one', 'two', 'missing']:
                        if user is None:
                            expected = (401, None)
                        elif rid == 'missing':
                            expected = (404, None)
                        elif (user, rid) in [('alice', 'one'), ('bob', 'two')]:
                            expected = (200, 'synthetic-A' if rid == 'one' else 'synthetic-B')
                        else:
                            expected = (403, None)
                        self.assertEqual(namespace['read_record'](user, rid), expected)

    def test_mutated_variants_fail_closed(self):
        for name, source in REVIEWED_FIXES.items():
            mutations = [source.replace('!=', '=='), source.replace('403', '200'),
                         source.replace('401', '403'), source.replace('404', '403'),
                         source.replace('synthetic-A', 'changed'), source + '\nimport os\n',
                         source.replace('return 200, record["value"]', 'return 200, RECORDS'),
                         source.replace('    record = RECORDS.get(record_id)',
                                        '    print(user)\n    record = RECORDS.get(record_id)')]
            for mutation in mutations:
                with self.subTest(name=name, source=mutation), self.assertRaises(PolicyError):
                    validate_proposal('blue', {'file': 'service.py', 'content': mutation})

    def test_owner_before_missing_guard_is_rejected(self):
        source = REVIEWED_FIXES['local-owner-user-first']
        source = source.replace('    owner = record["owner"]\n', '')
        source = source.replace('    if record is None:', '    owner = record["owner"]\n    if record is None:')
        with self.assertRaises(PolicyError):
            validate_proposal('blue', {'file': 'service.py', 'content': source})
