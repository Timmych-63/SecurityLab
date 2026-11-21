"""S11 research cycle tests: simulated model, simulated observer, real isolated Git.

Mocked model/observer prove mechanics only. Live model and Docker acceptance is
a separate step (see docs/S11_1_RESEARCH_CYCLE_RU.md).
"""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from securitylab.hermes_adapter import ProposalRejected
from securitylab.ai_contract import MODEL_DIGEST, digest
from securitylab.job_contract import parse_job
from securitylab.projects import add_project
from securitylab.policy import PolicyError
from securitylab.research_cycle import run_research_cycle, research_readiness
from securitylab.research_prepare import prepare_research
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store

HERE = Path(__file__).resolve().parents[1]
VULN = HERE / 'examples/s7_repos/authz_vulnerable'
FIX = (HERE / 'examples/s7_repos/authz_fixed/app/main.py').read_text(encoding='utf-8')
KNOWLEDGE = (
    '# Записи — база знаний приложения\n\n'
    '## Назначение\nПриложение отдаёт записи по GET /records/{record_id}. Данные в памяти.\n\n'
    '## Пользователи и права\nalice и bob — обычные пользователи. '
    'Обычный пользователь читает только свои записи; чужие записи должны отдаваться отказом 403.\n'
    'Отсутствующая идентификация (без X-Test-User) должна давать 401.\n\n'
    '## Границы документа\nРасположение дефектов и эталонные исправления отсутствуют.\n')
ACTORS = {'alice': 'user', 'bob': 'user'}
BUDGET = {'seconds': 600, 'decisions': 12, 'requests': 40}


class FakeResearchModel:
    """Scripted Red decisions and a Blue proposal; receipts are audit-consistent."""
    script = ['read', 'http', 'hypotheses']
    hypothesis_rows = [{'file': 'app/main.py', 'path': '/records/one', 'actor': 'bob',
                        'description': 'Bob reads a record owned by alice without ownership check',
                        'expected_status': 403,
                        'basis': 'Обычный пользователь читает только свои записи; отказ 403'}]
    blue_files = {'app/main.py': FIX}
    invalid_from = None
    omit_action = False
    last = None

    def __init__(self, cwd, output):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.calls = []
        self.count = 0
        FakeResearchModel.last = self

    def _receipt(self, req, value, status='PROPOSED'):
        identity = ('a' if req['role'] == 'red' else 'b') * 30 + '%02d' % (self.count % 100)
        record = {'id': identity, 'role': req['role'], 'status': status, 'cleanup': 'PASS',
                  'request_sha256': digest(req), 'attempt': 1,
                  'response': {'proposal': value, 'request_sha256': digest(req),
                               'model_digest': MODEL_DIGEST, 'tools': []}}
        (self.output / (identity + '.json')).write_text(json.dumps(record), encoding='utf-8')
        return record

    def ask(self, req, stop=lambda: False):
        self.calls.append(req)
        if self.invalid_from is not None and self.count >= self.invalid_from:
            self.count += 1
            return {'action': 'deploy_backdoor'}, self._receipt(req, {'action': 'x'},
                                                                status='BLOCKED')
        self.count += 1
        if req['role'] == 'red':
            step = self.script[min(self.count - 1, len(self.script) - 1)]
            if step == 'read':
                value = {'action': 'read', 'file': 'app/main.py', 'start': 1, 'count': 40}
            elif step == 'http':
                value = {'action': 'http', 'checks': [
                    {'path': '/records/one', 'actor': 'bob'},
                    {'path': '/records/one', 'actor': 'alice'}]}
            elif step == 'http_many':
                value = {'action': 'http', 'checks': [
                    {'path': '/records/one', 'actor': 'bob'},
                    {'path': '/records/one', 'actor': 'alice'},
                    {'path': '/records/two', 'actor': 'bob'}]}
            elif step == 'hypotheses_unprobed':
                # Live run #5: hypothesis about a pair the model never probed.
                value = {'action': 'hypotheses', 'hypotheses': [
                    {'file': 'app/main.py', 'path': '/records/two', 'actor': 'bob',
                     'description': 'Bob reads record two without a probe first',
                     'expected_status': 200,
                     'basis': 'Документация описывает только свои записи'}]}
            elif step == 'hypotheses_no_action':
                # Live run #7 (dashboard): the admitted final response omitted the
                # 'action' key; validate_reply admits that shape, so the core must
                # treat it as hypotheses instead of dying with KeyError('action').
                value = {'hypotheses': [dict(row) for row in self.hypothesis_rows]}
            else:
                value = {'action': 'hypotheses', 'hypotheses': [dict(row) for row in self.hypothesis_rows]}
                if self.omit_action:
                    value.pop('action')
        else:
            value = {'files': dict(self.blue_files)}
        return value, self._receipt(req, value)


class HermesFailureModel(FakeResearchModel):
    """Live run #1: decision 2 dies with a transport-level Hermes failure (truncated output)."""
    fail_at = 2
    def ask(self, req, stop=lambda: False):
        self.calls.append(req)
        if self.count + 1 >= self.fail_at:
            self.count += 1
            raise PolicyError('Hermes failed/interrupted: \u26a0\ufe0f Response truncated '
                              "(finish_reason='length') - model hit max output tokens; "
                              'BLOCKED: PolicyError: Hermes conversation failed')
        return super().ask(req, stop)


class WorkerRejectionModel(FakeResearchModel):
    """Live run #5: the container worker rejects the proposal before the envelope;
    the adapter raises ProposalRejected carrying the rejected proposal."""
    def ask(self, req, stop=lambda: False):
        step = self.script[min(self.count, len(self.script) - 1)]
        if step == 'hypotheses_unprobed':
            self.count += 1
            self.calls.append(req)
            bad = {'action': 'hypotheses', 'hypotheses': [
                {'file': 'app/main.py', 'path': '/records/two', 'actor': 'bob',
                 'description': 'unprobed pair', 'expected_status': 200, 'basis': 'doc'}]}
            raise ProposalRejected(
                'red attempt 2: proposal rejected; see call receipt x: '
                'Hypothesis must reference an HTTP observation you made in this research run',
                'note', proposal=bad, receipt_id='c' * 32)
        return super().ask(req, stop)


class FakeObserver:
    """Synthetic stand: bob reads alice's record until the patch adds the owner check."""
    def __init__(self):
        self.calls = []
        self.fixed_from_call = None

    def __call__(self, folder, payload, checks, binding, *, broker_factory, limits, stop=None):
        stage = folder.name
        self.calls.append(stage)
        code = parse_job(payload)['files']['app/main.py']
        fixed = "x_test_user != record['owner']" in code
        if self.fixed_from_call is not None and len(self.calls) > self.fixed_from_call:
            fixed = True
        observations = []
        for check in checks:
            key = check['path'].rsplit('/', 1)[-1]
            owner = 'alice' if key == 'one' else 'bob'
            if check['actor'] is None:
                status = 401
            elif key not in ('one', 'two'):
                status = 404
            elif check['actor'] == owner:
                status = 200
            else:
                status = 403 if fixed else 200
            if status == 200:
                data = json.dumps({'id': key, 'owner': owner,
                                   'value': 'synthetic-A' if key == 'one' else 'synthetic-B'},
                                  separators=(',', ':')).encode()
            else:
                data = json.dumps({'detail': {401: 'Unauthorized', 403: 'Forbidden',
                                              404: 'Not Found'}[status]},
                                  separators=(',', ':')).encode()
            observations.append({'actor': check['actor'], 'path': check['path'],
                                 'expected_status': check['expected_status'],
                                 'actual_status': status,
                                 'body_bytes': len(data), 'body_truncated': False,
                                 'body_sha256': hashlib.sha256(data).hexdigest(),
                                 'passed': status == check['expected_status'], 'error': None})
        receipt = {'binding': binding, 'stage': stage, 'simulated': True}
        raw = json.dumps(receipt).encode()
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'docker_receipt.json').write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        return {'status': 'HTTP_CHECKS_PASSED' if all(x['passed'] for x in observations)
                else 'HTTP_CHECKS_FAILED',
                'observations': observations,
                'image_id': 'sha256:' + '1' * 64,
                'target_image_id': 'sha256:' + '2' * 64,
                'cleanup': 'PASS', 'receipt_sha256': sha}


class ResearchFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.src = self.root / 'project'
        shutil.copytree(VULN, self.src)
        self.store = Store(self.root / 'state')
        self.addCleanup(self.store.close)
        pid = add_project(self.store, self.src, 'Research test')['id']
        self.sid = create_snapshot(self.store, pid)['snapshot_id']
        self.observer = FakeObserver()
        self.saved = {k: getattr(FakeResearchModel, k)
                      for k in ('script', 'hypothesis_rows', 'blue_files', 'invalid_from',
                                'omit_action')}
        self.addCleanup(self._restore)

    def _restore(self):
        for k, v in self.saved.items():
            setattr(FakeResearchModel, k, v)

    def prepare(self, budget=None):
        return prepare_research(
            self.store, self.sid, 'app/main.py', knowledge_text=KNOWLEDGE,
            setup_value={'schema_version': 1, 'runtime': 'fastapi-local-v1',
                         'identity': 'trusted-test-user-header', 'actors': dict(ACTORS),
                         'budget': dict(budget or BUDGET)})

    def run_cycle(self, prep_id, **kwargs):
        return run_research_cycle(self.store, prep_id, execute=True,
                                  adapter_factory=FakeResearchModel, observer=self.observer,
                                  **kwargs)


class FullCycleTests(ResearchFixture):
    def test_self_directed_cycle_pass_with_confirmed_and_fixed(self):
        original = (self.src / 'app/main.py').read_bytes()
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'PASS', result.get('error'))
        self.assertEqual(result['finding_status'], 'FIXED')
        self.assertEqual(result['security_verdict'], 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX')
        states = [h['state'] for h in result['hypotheses']]
        self.assertEqual(states, ['confirmed'])
        self.assertEqual(result['hypotheses'][0]['observed_status'], 200)
        self.assertEqual(result['hypotheses'][0]['observed_stage'], 'http_02')
        self.assertEqual(result['hypotheses'][0]['confirm_status'], 200)
        self.assertEqual(result['hypotheses'][0]['confirm_stage'], 'confirm')
        self.assertEqual(self.observer.calls,
                         ['http_02', 'confirm', 'baseline', 'candidate', 'recheck'])
        self.assertEqual(result['stages']['confirm']['status'], 'HTTP_CHECKS_PASSED')
        self.assertEqual(result['stages']['baseline']['status'], 'ACCESS_POLICY_VIOLATION_REPRODUCED')
        self.assertEqual(result['stages']['candidate']['status'], 'ACCESS_POLICY_MATCHED')
        self.assertEqual(result['stages']['recheck']['status'], 'ACCESS_POLICY_MATCHED')
        coverage = result['coverage']
        self.assertEqual(coverage['decisions_used'], 3)
        self.assertEqual(coverage['requests_used'], 2)
        self.assertGreaterEqual(coverage['verification_requests'], 7)
        self.assertEqual(coverage['budget'], BUDGET)
        # The source repository is untouched; the patch lives only in the isolated copy.
        self.assertEqual((self.src / 'app/main.py').read_bytes(), original)
        self.assertFalse(result['git']['merged'])
        self.assertIn("x_test_user != record['owner']", result['git']['diff'])
        saved = json.loads(Path(result['record']).read_text(encoding='utf-8'))
        self.assertEqual(saved['status'], 'PASS')
        first_red = FakeResearchModel.last.calls[0]
        self.assertEqual(first_red['knowledge'], KNOWLEDGE)
        # The map lists file names and routes, never source contents.
        self.assertNotIn('RECORDS', json.dumps(first_red['map']))
        self.assertNotIn('HTTPException', json.dumps(first_red['map']))
        self.assertEqual(first_red['budget']['decisions_left'], 12)  # до первого решения

    def test_no_hypotheses_is_honest_done_not_pass(self):
        FakeResearchModel.script = ['read', 'hypotheses']
        FakeResearchModel.hypothesis_rows = []
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(result['security_verdict'], 'NOT_EVALUATED')
        self.assertIsNone(result['finding_status'])
        self.assertNotIn('confirm', self.observer.calls)
        self.assertNotIn('candidate', self.observer.calls)

    def test_refuted_when_fresh_stand_disagrees(self):
        FakeResearchModel.script = ['http', 'hypotheses']
        # The fresh confirmation stand behaves like the fixed app: 403 for bob.
        self.observer.fixed_from_call = 1
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(result['stop_reason'], 'no_reproduced_violations')
        self.assertEqual(result['hypotheses'][0]['state'], 'refuted')
        self.assertEqual(result['security_verdict'], 'NOT_EVALUATED')

    def test_consistent_hypothesis_skips_fresh_stand_and_records_stage(self):
        # Live run #6: the only hypothesis matched the documentation (observed 200,
        # expected 200), the run finished DONE and no fresh stand ran; the UI must
        # be able to say WHY the 'Свежий стенд' column is empty instead of a bare dash.
        FakeResearchModel.script = ['http', 'hypotheses']
        FakeResearchModel.hypothesis_rows = [
            {'file': 'app/main.py', 'path': '/records/one', 'actor': 'alice',
             'description': 'Owner reads own record', 'expected_status': 200,
             'basis': 'Обычный пользователь читает только свои записи'}]
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(result['stop_reason'], 'no_violation_hypotheses')
        self.assertEqual(result['hypotheses'][0]['state'], 'consistent')
        self.assertEqual(result['hypotheses'][0]['observed_stage'], 'http_01')
        self.assertIsNone(result['hypotheses'][0]['confirm_stage'])
        self.assertIsNone(result['hypotheses'][0]['confirm_status'])
        self.assertNotIn('confirm', self.observer.calls)

    def test_final_hypotheses_without_action_key_complete_the_cycle(self):
        # Live run #7 (dashboard): the model's admitted final response was
        # {"hypotheses": [...]} without the "action" key; the loop died on
        # KeyError('action') and the dashboard showed "Причина: 'action'".
        # validate_reply deliberately admits that shape, so the core must treat
        # it as the final hypotheses object and continue to Blue as usual.
        FakeResearchModel.omit_action = True
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertNotIn('KeyError', str(result.get('error')))
        self.assertEqual(result['status'], 'PASS', result.get('error'))
        self.assertEqual(result['finding_status'], 'FIXED')
        self.assertEqual(result['coverage']['decisions_used'], 3)
        saved = json.loads(Path(result['record']).read_text(encoding='utf-8'))
        self.assertEqual(saved['status'], 'PASS')
        # После гипотез без 'action' цикл дошёл до Blue: предпоследний вызов — Red, последний — Blue.
        self.assertEqual(FakeResearchModel.last.calls[-2]['role'], 'red')
        self.assertEqual(FakeResearchModel.last.calls[-1]['role'], 'blue')

    def test_authznotes_scenario_package_prepares(self):
        # The S11.3 live Blue scenario: real knowledge/setup files from
        # examples/research must pass preparation against the authz app.
        knowledge = (HERE / 'examples/research/authznotes.md').read_text(encoding='utf-8')
        setup = json.loads((HERE / 'examples/research/authznotes.setup.json').read_text(encoding='utf-8'))
        prep = prepare_research(self.store, self.sid, 'app/main.py',
                                knowledge_text=knowledge, setup_value=setup)
        self.assertEqual(prep['status'], 'PREPARED')
        self.assertFalse(prep['execution_ready'])


class ErrorAndBudgetTests(ResearchFixture):
    def test_format_error_blocked_with_saved_progress(self):
        FakeResearchModel.script = ['read', 'read', 'read']
        FakeResearchModel.invalid_from = 2  # every reply from the 3rd call is garbage
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'BLOCKED')
        # Live run #5 semantics: one wasted decision is tolerated (the reason
        # lands in the model-visible history); the second consecutive rejected
        # decision stops the run with everything saved.
        self.assertIn('отклонён в двух решениях подряд', result['error'])
        self.assertEqual(result['coverage']['decisions_used'], 4)
        folder = Path(result['record']).parent
        self.assertTrue((folder / 'decision_01.json').exists())
        rejected = json.loads((folder / 'decision_03.json').read_text(encoding='utf-8'))
        self.assertTrue(rejected['action']['rejected'])
        self.assertIn('Only read, search, http', rejected['result']['reason'])
        self.assertEqual(len([c for c in result['ai_calls'] if c.get('rejected')]), 4)

    def test_unobserved_hypothesis_pairs_get_autoprobed(self):
        # Live run #5: decision 1 probed one batch, decision 2 hypothesized about
        # an unprobed pair and the run died twice-rejected. Now the core probes
        # the missing pair itself and the re-ask completes the cycle.
        FakeResearchModel.script = ['http', 'hypotheses_unprobed', 'hypotheses']
        prep = self.prepare()
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'PASS', result.get('error'))
        self.assertEqual(self.observer.calls,
                         ['http_01', 'http_assist_02', 'confirm', 'baseline',
                          'candidate', 'recheck'])
        self.assertEqual(result['coverage']['requests_used'], 3)
        self.assertEqual(result['coverage']['decisions_used'], 2)
        self.assertEqual(result['stages']['http_assist_02']['status'], 'HTTP_CHECKS_PASSED')
        self.assertEqual(result['hypotheses'][0]['state'], 'confirmed')
        rejected = [c for c in result['ai_calls'] if c.get('rejected')]
        self.assertEqual(len(rejected), 1)
        self.assertIn('Hypothesis must reference an HTTP observation', rejected[0]['reason'])

    def test_worker_side_rejection_autoprobed_and_run_continues(self):
        # The real transport path: worker-side validation rejects before the
        # envelope; ProposalRejected carries the proposal and receipt id.
        FakeResearchModel.script = ['http', 'hypotheses_unprobed', 'hypotheses']
        prep = self.prepare()
        result = run_research_cycle(self.store, prep['id'], execute=True,
                                    adapter_factory=WorkerRejectionModel,
                                    observer=self.observer)
        self.assertEqual(result['status'], 'PASS', result.get('error'))
        self.assertEqual(self.observer.calls,
                         ['http_01', 'http_assist_02', 'confirm', 'baseline',
                          'candidate', 'recheck'])
        rejected = [c for c in result['ai_calls'] if c.get('rejected')]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]['id'], 'c' * 32)

    def test_hermes_transport_failure_blocked_with_saved_progress(self):
        # Mirrors live run #1: decision 1 makes an HTTP observation, decision 2 dies
        # with a truncated model output. Progress must survive the BLOCKED result.
        FakeResearchModel.script = ['http', 'hypotheses']
        prep = self.prepare()
        result = run_research_cycle(self.store, prep['id'], execute=True,
                                    adapter_factory=HermesFailureModel, observer=self.observer)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('Hermes failed/interrupted', result['error'])
        self.assertEqual(result['coverage']['decisions_used'], 1)
        self.assertEqual(result['coverage']['requests_used'], 2)  # bob + alice in one batch
        folder = Path(result['record']).parent
        decision = json.loads((folder / 'decision_01.json').read_text(encoding='utf-8'))
        self.assertEqual(decision['action']['action'], 'http')
        self.assertTrue(decision['raw_observations'])
        self.assertEqual(result['stages']['http_01']['status'], 'HTTP_CHECKS_PASSED')
        self.assertEqual(self.observer.calls, ['http_01'])

    def test_decision_budget_exhaustion_keeps_results(self):
        FakeResearchModel.script = ['read', 'read', 'read', 'read']
        prep = self.prepare(budget={'seconds': 600, 'decisions': 2, 'requests': 40})
        result = self.run_cycle(prep['id'])
        self.assertEqual(result['status'], 'DONE')
        self.assertEqual(result['stop_reason'], 'budget_decisions_exhausted')
        self.assertEqual(result['coverage']['decisions_used'], 2)
        self.assertEqual(result['security_verdict'], 'NOT_EVALUATED')

    def test_request_budget_limits_http_batch(self):
        FakeResearchModel.script = ['http_many', 'hypotheses']
        prep = self.prepare(budget={'seconds': 600, 'decisions': 6, 'requests': 2})
        result = self.run_cycle(prep['id'])
        # Verification budget is separate: confirm/blue still complete the cycle.
        self.assertEqual(result['status'], 'PASS', result.get('error'))
        self.assertEqual(result['coverage']['requests_used'], 2)
        self.assertEqual(len(result['stages']['http_01']['observations']), 2)
        self.assertEqual(result['hypotheses'][0]['state'], 'confirmed')

    def test_cancelled_cycle_reports_stopped(self):
        prep = self.prepare()
        result = run_research_cycle(self.store, prep['id'], execute=True,
                                    adapter_factory=FakeResearchModel, observer=self.observer,
                                    stop=lambda: True)
        self.assertEqual(result['status'], 'STOPPED')
        self.assertEqual(result['stop_reason'], 'cancelled')

    def test_superseded_preparation_rejected(self):
        prep1 = self.prepare()
        prep2 = self.prepare()
        result = self.run_cycle(prep1['id'])
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('более новой подготовкой', result['error'])
        ok = self.run_cycle(prep2['id'])
        self.assertEqual(ok['status'], 'PASS', ok.get('error'))

    def test_readiness_checks_static_layers(self):
        prep = self.prepare()
        ready = research_readiness(self.store, prep['id'])
        self.assertTrue(ready['ready'])
        self.assertEqual(ready['prepare'], 'verified')
        self.assertEqual(ready['project'], 'verified')
        self.assertIn('маршрутов', ready['details']['project'])
        broken = self.root / 'broken'
        (broken / 'app').mkdir(parents=True)
        (broken / 'app/__init__.py').write_text('', encoding='utf-8')
        (broken / 'app/main.py').write_text(
            'import requests\nfrom fastapi import FastAPI\napp=FastAPI()\n'
            '@app.get("/x")\ndef x():\n    return requests.get("http://example.com").text\n',
            encoding='utf-8')
        from securitylab.policy import PolicyError
        pid = add_project(self.store, broken, 'Broken')['id']
        sid = create_snapshot(self.store, pid)['snapshot_id']
        with self.assertRaises(PolicyError) as ctx:
            prepare_research(self.store, sid, 'app/main.py', knowledge_text=KNOWLEDGE,
                             setup_value={'schema_version': 1, 'runtime': 'fastapi-local-v1',
                                          'identity': 'trusted-test-user-header',
                                          'actors': dict(ACTORS), 'budget': dict(BUDGET)})
        self.assertIn('requests', str(ctx.exception))
        # Tampering with the saved snapshot after preparation invalidates readiness.
        (self.store.root / 'snapshots' / self.sid / 'workspace' / 'app' / 'main.py').write_text(
            'changed', encoding='utf-8')
        stale = research_readiness(self.store, prep['id'])
        self.assertFalse(stale['ready'])
        self.assertEqual(stale['project'], 'error')
        self.assertTrue(stale['details']['project'])


if __name__ == '__main__':
    unittest.main()
