"""S11 research contract tests: validation, budget, format feedback, transport bounds."""
import json
import unittest

from securitylab import research_contract as contract
from securitylab.policy import PolicyError

MAP = {'entry': 'app/main.py', 'files': ['app/main.py'],
       'routes': [{'method': 'GET', 'path': '/records/{record_id}', 'file': 'app/main.py'}],
       'dependencies': ['fastapi']}
ACTORS = ['alice', 'bob']
KNOWLEDGE = 'Приложение: чтение записей. Обычный пользователь читает только свои записи.'
BUDGET = {'decisions_left': 10, 'requests_left': 10, 'seconds_left': 600}


def _request(history=None, **kwargs):
    return contract.make_request('app/main.py', MAP, KNOWLEDGE, history or [], kwargs.pop('budget', BUDGET),
                                 kwargs.pop('actors', ACTORS), **kwargs)


class RedRequestTests(unittest.TestCase):
    def test_request_roundtrip_and_bounds(self):
        req = _request()
        self.assertEqual(req['task'], contract.TASK_RED)
        contract.validate_request(req)
        contract.prompt(req)  # prompt must not raise on a valid request
        with self.assertRaises(PolicyError):
            _request(budget={'decisions_left': -1, 'requests_left': 0, 'seconds_left': 0})
        with self.assertRaises(PolicyError):
            _request(actors=['alice', 'bad name!'])

    def test_transport_bound_rejects_oversized_knowledge(self):
        with self.assertRaises(PolicyError):
            contract.make_request('app/main.py', MAP, 'x' * 13000, [], BUDGET, ACTORS)

    def test_compact_request_trims_history_and_drops_oldest(self):
        rows = []
        for i in range(20):
            rows.append({'n': i + 1, 'action': 'read',
                         'result': {'file': 'app/main.py', 'text': 'line\n' * 400}})
        draft = dict(task=contract.TASK_RED, schema_version=1, role='red', entry='app/main.py',
                     map=MAP, knowledge=KNOWLEDGE, history=rows, budget=BUDGET, actors=ACTORS)
        trimmed = contract.compact_request(draft)
        self.assertLessEqual(len(json.dumps(trimmed, ensure_ascii=False).encode()), contract.TRANSPORT_BYTES)
        self.assertTrue(trimmed['history'])
        self.assertLess(len(trimmed['history']), len(rows))
        contract.validate_request(trimmed)


class RedReplyTests(unittest.TestCase):
    HTTP_HISTORY = [{'n': 1, 'action': 'http', 'result': {'observations': [
        {'path': '/records/one', 'actor': 'bob', 'status': 200},
        {'path': '/records/one', 'actor': 'alice', 'status': 200}]}}]

    def test_read_search_http_actions_validated(self):
        req = _request()
        contract.validate_reply(req, {'action': 'read', 'file': 'app/main.py', 'start': 1, 'count': 40})
        contract.validate_reply(req, {'action': 'search', 'query': 'x_test_user'})
        contract.validate_reply(req, {'action': 'http', 'checks': [
            {'path': '/records/one', 'actor': 'bob'}, {'path': '/records/one', 'actor': None}]})
        for bad in [{'action': 'read', 'file': 'app/other.py', 'start': 1, 'count': 5},
                    {'action': 'read', 'file': 'app/main.py', 'start': 0, 'count': 5},
                    {'action': 'search', 'query': ''},
                    {'action': 'http', 'checks': [{'path': '/x/{id}', 'actor': None}]},
                    {'action': 'shell', 'command': 'rm -rf /'},
                    {'action': 'http', 'checks': [{'path': '/records/one', 'actor': 'intruder'}]}]:
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                contract.validate_reply(req, bad)

    def test_hypotheses_require_own_observation(self):
        req = _request(history=self.HTTP_HISTORY)
        row = {'file': 'app/main.py', 'path': '/records/one', 'actor': 'bob',
               'description': 'Bob reads a foreign record without ownership check',
               'expected_status': 403, 'basis': 'Обычный пользователь читает только свои записи'}
        contract.validate_reply(req, {'action': 'hypotheses', 'hypotheses': [row]})
        contract.validate_reply(req, {'action': 'hypotheses', 'hypotheses': [],
                                      'note': 'ничего подозрительного'})
        stale = _request()
        with self.assertRaises(PolicyError):
            contract.validate_reply(stale, {'action': 'hypotheses', 'hypotheses': [row]})
        for bad in [{'file': 'app/other.py', 'path': '/records/one', 'actor': 'bob',
                     'description': 'x', 'expected_status': 403, 'basis': 'y'},
                    {'file': 'app/main.py', 'path': '/records/{record_id}', 'actor': 'bob',
                     'description': 'x', 'expected_status': 403, 'basis': 'y'},
                    {'file': 'app/main.py', 'path': '/records/one', 'actor': 'admin',
                     'description': 'x', 'expected_status': 403, 'basis': 'y'},
                    {'file': 'app/main.py', 'path': '/records/one', 'actor': 'bob',
                     'description': 'x', 'expected_status': 500, 'basis': 'y'}]:
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                contract.validate_reply(req, {'action': 'hypotheses', 'hypotheses': [bad]})

    def test_retry_request_appends_feedback_once(self):
        req = _request()
        retry = contract.retry_request(req, 'bad action')
        self.assertEqual(retry['retry'], 'bad action')
        contract.validate_request(retry)
        with self.assertRaises(PolicyError):
            contract.retry_request(retry, 'again')


class BlueTests(unittest.TestCase):
    FILES = {'app/main.py': 'x = 1\n'}

    def _problems(self):
        return [{'id': 'deny-1', 'file': 'app/main.py', 'path': '/records/one', 'actor': 'bob',
                 'expected_status': 403, 'observed_status': 200,
                 'description': 'foreign read', 'basis': 'documentation'}]

    def test_blue_request_and_reply(self):
        req = contract.make_blue_request('app/main.py', self.FILES, self._problems(),
                                         KNOWLEDGE, [{'path': '/records/one', 'actor': 'bob',
                                                      'actual_status': 200}])
        contract.blue_prompt(req)
        contract.validate_blue_reply(req, {'files': {'app/main.py': 'x = 2\n'}})
        for bad in [{'files': {}},
                    {'files': {'app/main.py': self.FILES['app/main.py']}},
                    {'files': {'app/extra.py': 'x = 3\n'}},
                    {'other': 1}]:
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                contract.validate_blue_reply(req, bad)

    def test_blue_problem_bounds(self):
        with self.assertRaises(PolicyError):
            contract.make_blue_request('app/main.py', self.FILES, self._problems(), KNOWLEDGE,
                                       [{'path': 1, 'actor': 'bob', 'actual_status': 200}])
        problems = self._problems()
        problems[0]['expected_status'] = 404
        with self.assertRaises(PolicyError):
            contract.make_blue_request('app/main.py', self.FILES, problems, KNOWLEDGE, [])

    def test_blue_feedback_and_retry(self):
        req = contract.make_blue_request('app/main.py', self.FILES, self._problems(),
                                         KNOWLEDGE, [])
        self.assertTrue(contract.blue_feedback(req, {'files': {'app/main.py': 'x = 1\n'}})[0])
        retry = contract.retry_request(req, 'failed verification')
        self.assertEqual(retry['retry'], 'failed verification')
        with self.assertRaises(PolicyError):
            contract.retry_request(retry, 'second')

    def test_research_tasks_registered_in_proposal_modes(self):
        from securitylab import proposal_modes
        req = _request()
        self.assertIn(req['task'], ('s11-research-red-v1',))
        self.assertIs(proposal_modes.contract(req), contract)
        blue = contract.make_blue_request('app/main.py', self.FILES, self._problems(), KNOWLEDGE, [])
        self.assertIs(proposal_modes.contract(blue), contract)
        self.assertIn('hypotheses', proposal_modes.proposal_prompt(req))
        self.assertIn('files', proposal_modes.proposal_prompt(blue))
        self.assertTrue(proposal_modes.proposal_system(blue))


class CorrectiveInstructionTests(unittest.TestCase):
    """Live run #5: schema rejections must hand the model the canonical shapes."""

    def test_red_instruction_bounded_with_shapes(self):
        note = contract.corrective_instruction(
            'Each http check needs exactly path and actor (actor may be null)')
        self.assertIn('Each http check needs exactly', note)
        self.assertIn('{"action":"http","checks":[{"path":"/records/one","actor":null}]}', note)
        self.assertIn('exactly one compact valid JSON', note)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)
        contract.validate_request(contract.retry_request(_request(), note))

    def test_red_instruction_survives_oversized_reason(self):
        note = contract.corrective_instruction('y' * 6000)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)
        contract.validate_request(contract.retry_request(_request(), note))

    def test_blue_instruction_bounded(self):
        note = contract.blue_corrective_instruction(
            'Patch must change only files selected for Blue')
        self.assertIn('{"files"', note)
        self.assertIn('Patch must change only files', note)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)

    def test_prompt_names_exact_http_check_keys(self):
        prompt = contract.prompt(_request())
        self.assertIn('exactly the keys path and actor', prompt)
        self.assertIn('never method, headers, file or notes', prompt)


class ObservationGuidanceTests(unittest.TestCase):
    """S11.2: unobserved hypothesis pairs must self-heal, not kill the run."""

    HTTP_HISTORY = [{'n': 1, 'action': 'http', 'result': {'observations': [
        {'path': '/records/one', 'actor': 'bob', 'status': 200}]}}]

    def test_observed_pairs_extracted_from_history(self):
        self.assertEqual(contract.observed_pairs(self.HTTP_HISTORY),
                         [{'path': '/records/one', 'actor': 'bob', 'status': 200}])
        self.assertEqual(contract.observed_pairs(None), [])
        self.assertEqual(contract.observed_pairs([{'n': 1, 'result': {'text': 'x'}}]), [])
        self.assertEqual(contract.observed_pairs([{'n': 1, 'result': {'observations': [
            {'path': '/a', 'actor': None, 'status': 401},
            {'path': '/a', 'actor': None, 'status': 401}]}}]),
            [{'path': '/a', 'actor': None, 'status': 401}])

    def test_missing_hypothesis_pairs(self):
        value = {'action': 'hypotheses', 'hypotheses': [
            {'path': '/records/one', 'actor': 'bob'},
            {'path': '/records/two', 'actor': 'bob'},
            {'path': '/records/two', 'actor': 'alice'}]}
        self.assertEqual(contract.missing_hypothesis_pairs(value, self.HTTP_HISTORY),
                         [{'path': '/records/two', 'actor': 'bob'},
                          {'path': '/records/two', 'actor': 'alice'}])
        self.assertEqual(contract.missing_hypothesis_pairs({'hypotheses': []},
                                                           self.HTTP_HISTORY), [])
        self.assertEqual(contract.missing_hypothesis_pairs({'action': 'read'},
                                                           self.HTTP_HISTORY), [])

    def test_prompt_lists_observed_checks(self):
        prompt = contract.prompt(_request(history=self.HTTP_HISTORY))
        self.assertIn('OBSERVED HTTP CHECKS', prompt)
        self.assertIn('"/records/one"', prompt)
        empty = contract.prompt(_request())
        self.assertIn('probe a new pair first): []', empty)
        self.assertIn('first run an http action with exactly that pair', empty)

    def test_compact_request_never_drops_observation_rows_first(self):
        rows = [{'n': 1, 'action': 'http', 'result': {'observations': [
            {'path': '/records/one', 'actor': 'bob', 'status': 200}]}}]
        for i in range(20):
            rows.append({'n': i + 2, 'action': 'read',
                         'result': {'file': 'app/main.py', 'text': 'line\n' * 400}})
        draft = dict(task=contract.TASK_RED, schema_version=1, role='red', entry='app/main.py',
                     map=MAP, knowledge=KNOWLEDGE, history=rows, budget=BUDGET, actors=ACTORS)
        trimmed = contract.compact_request(draft)
        self.assertLessEqual(len(json.dumps(trimmed, ensure_ascii=False).encode()),
                             contract.TRANSPORT_BYTES)
        self.assertTrue(any(isinstance(r.get('result'), dict)
                            and 'observations' in r['result'] for r in trimmed['history']))

    def test_corrective_instruction_names_missing_and_observed(self):
        req = _request(history=self.HTTP_HISTORY)
        value = {'action': 'hypotheses', 'hypotheses': [{'path': '/records/two', 'actor': 'bob'}]}
        note = contract.corrective_instruction(
            'Hypothesis must reference an HTTP observation you made in this research run',
            req=req, value=value)
        self.assertIn('"/records/two"', note)
        self.assertIn('OBSERVED HTTP CHECKS', note)
        self.assertIn('"/records/one"', note)
        self.assertIn('first return {"action":"http"', note)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)
        contract.validate_request(contract.retry_request(req, note))

    def test_corrective_instruction_single_arg_still_bounded(self):
        note = contract.corrective_instruction('x' * 300)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)
        contract.validate_request(contract.retry_request(_request(), note))

    def test_assist_retry_note_bounded_and_valid_retry(self):
        note = contract.assist_retry_note([{'path': '/records/two', 'actor': 'bob'}])
        self.assertIn('"/records/two"', note)
        self.assertIn('OBSERVED HTTP CHECKS', note)
        self.assertLessEqual(len(note.encode('utf-8')), 2000)
        contract.validate_request(contract.retry_request(_request(), note))


class SuggestionTests(unittest.TestCase):
    """S11.3: category navigation for Red, derived from map+actors only (run #6)."""

    MULTI_MAP = {'entry': 'app/main.py', 'files': ['app/main.py'],
                 'routes': [{'method': 'GET', 'path': '/records/{record_id}', 'file': 'app/main.py'},
                            {'method': 'GET', 'path': '/health', 'file': 'app/main.py'},
                            {'method': 'POST', 'path': '/records', 'file': 'app/main.py'}],
                 'dependencies': ['fastapi']}

    def _req(self, history=None):
        return contract.make_request('app/main.py', self.MULTI_MAP, KNOWLEDGE,
                                     history or [], BUDGET, ACTORS)

    def test_categories_ordered_and_templates_instantiated(self):
        rows = contract.probe_suggestions(self._req())
        # Anonymous over documented routes first, then each account.
        self.assertEqual([r['actor'] for r in rows][:4], [None, None, 'alice', 'alice'])
        self.assertEqual(rows[0], {'path': '/health', 'actor': None})
        self.assertIn({'path': '/records/probe-0', 'actor': None}, rows)
        # Non-GET routes never suggest checks: 2 GET routes x 3 actor groups.
        self.assertEqual(len(rows), 6)
        self.assertEqual([r['path'] for r in rows].count('/records/probe-0'), 3)
        self.assertFalse(any(r['path'].endswith('{record_id}') for r in rows))

    def test_observed_pairs_excluded_and_limit_respected(self):
        history = [{'n': 1, 'action': 'http', 'result': {'observations': [
            {'path': '/health', 'actor': None, 'status': 200}]}}]
        rows = contract.probe_suggestions(self._req(history))
        self.assertNotIn({'path': '/health', 'actor': None}, rows)
        self.assertEqual(len(rows), 5)  # 6 candidates minus the observed pair
        capped = contract.probe_suggestions(self._req(), limit=3)
        self.assertEqual(len(capped), 3)

    def test_suggestions_carry_no_source_or_knowledge_content(self):
        knowledge = 'SECRET-OWNER-CHECK-STRING records owner value synthetic'
        req = contract.make_request('app/main.py', self.MULTI_MAP, knowledge, [], BUDGET, ACTORS)
        rows = contract.probe_suggestions(req)
        self.assertNotIn('SECRET', json.dumps(rows))
        self.assertTrue(all(set(r) == {'path', 'actor'} for r in rows))
        self.assertTrue(all(r['path'].startswith('/') for r in rows))

    def test_prompt_shows_suggestions_and_category_rule(self):
        prompt = contract.prompt(self._req())
        self.assertIn('SUGGESTED NEXT PROBES', prompt)
        self.assertIn('not obligations and not defect hints', prompt)
        self.assertIn('Study the DOCUMENTATION systematically', prompt)
        self.assertIn('/records/probe-0', prompt)
        self.assertIn('/health', prompt)


if __name__ == '__main__':
    unittest.main()
