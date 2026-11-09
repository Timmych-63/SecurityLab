import json
import unittest
from securitylab.ai_contract import blue_feedback, prompt, request, validate_proposal, digest
from securitylab.policy import PolicyError
from securitylab.hermes_worker import invoke

RED = dict(file='service.py', description='INCORRECT_UNTRUSTED_PROSE', user='attacker', record_id='one')
BAD_SOURCE = '''import os
from typing import Optional, Tuple

def read_record(user: str, record_id: str) -> Tuple[int, Optional[dict]]:
    if user is None:
        return 401, None
    owner = os.path.getattruser(record_id)
    if owner != user:
        return 403, None
    record = RECORDS.get(record_id)
    if record is None:
        return 404, None
    return 200, record["value"]
'''
BAD = dict(file='service.py', content=BAD_SOURCE, schema_version=1, role='blue',
           verification='actual-candidate-v1', source='RECORDS_COPY', left=[])

class BluePromptTests(unittest.TestCase):
    def test_last_user_response_stays_rejected(self):
        with self.assertRaisesRegex(PolicyError,'schema/path'):
            validate_proposal('blue',BAD,candidate=True)
        with self.assertRaises(PolicyError):
            validate_proposal('blue',dict(file='service.py',content=BAD_SOURCE),candidate=True)

    def test_feedback_collects_schema_and_code_problems(self):
        text='\n'.join(blue_feedback(BAD,candidate=True))
        for expected in ['Return only file', 'RECORDS assignment', 'without annotations',
                         'Remove imports', 'Remove unsupported calls', 'first three function statements']:
            self.assertIn(expected,text)
        self.assertNotIn('os.path.getattruser',text)

    def test_transport_and_rejected_fields_never_enter_prompt(self):
        req=request('blue',RED,json.dumps(BAD),candidate=True)
        query=prompt(req)
        for value in ['schema_version','actual-candidate-v1','RECORDS_COPY',
                      'os.path.getattruser','INCORRECT_UNTRUSTED_PROSE','"left"','"role"']:
            self.assertNotIn(value,query)
        self.assertIn('ORIGINAL MODULE',query)
        self.assertIn('"user": "attacker"',query)
        self.assertIn('RECORDS assignment',query)
        legacy=request('blue',RED,json.dumps(BAD))
        self.assertNotEqual(digest(req),digest(legacy))

    def test_malformed_and_oversized_content_bounded(self):
        for value in [None,{},dict(file='x',content=2),dict(file='x',content='x'*12001),
                      dict(file='x',content='def broken(')]:
            notes=blue_feedback(value,candidate=True)
            self.assertTrue(notes)
            self.assertLess(len(json.dumps(notes)),3000)

    def test_worker_uses_new_prompt_and_still_rejects(self):
        from test_ai import Agent
        class BadAgent(Agent):
            tool_list=[];messages=[];reply=json.dumps(BAD)
            def run_conversation(self,**kwargs):
                self.query=kwargs['user_message']
                return super().run_conversation(**kwargs)
        with self.assertRaises(PolicyError):invoke(request('blue',RED,candidate=True),BadAgent)
        self.assertNotIn('actual-candidate-v1',BadAgent.instances[-1].query)
