"""Deterministic demo validator; no role can submit a FIXED flag."""
from .fixture import digest, SUITE, FIXED, VULNERABLE, REGRESSION

BASE_CHECKS = {'owner_read', 'other_owner_read', 'anonymous_rejected', 'missing_record'}
ACCESS_CHECKS = {'cross_user_denied', 'reverse_cross_user_denied', 'unknown_user_denied'}
ALL_CHECKS = BASE_CHECKS | ACCESS_CHECKS


def result_ok(evidence, code=0):
    r = evidence.get('result', {})
    return (type(r.get('returncode')) is int and r['returncode'] == code
            and all(r.get(x) is False for x in ('timed_out', 'cancelled', 'truncated')))


def confirmed(e):
    checks = e.get('checks', {})
    return (result_ok(e, 1) and e.get('source_hash') == digest(VULNERABLE)
            and e.get('test_hash') == digest(SUITE) and set(checks) == ALL_CHECKS
            and all(checks[k] is True for k in BASE_CHECKS)
            and all(checks[k] is False for k in ACCESS_CHECKS)
            and e.get('observed') == [200, 'synthetic-B'])


def validate(evidence, current_revision, clean, main_revision):
    reasons = []
    baseline = evidence.get('baseline', {})
    if not confirmed(baseline):
        reasons.append('Baseline does not prove the known access violation')
    if evidence.get('patch', {}).get('revision') != current_revision:
        reasons.append('Patch commit does not match current revision')
    if not clean:
        reasons.append('Working tree is dirty')
    if baseline.get('revision') != main_revision or main_revision == current_revision:
        reasons.append('Main branch or revision relationship is invalid')
    for name in ('recheck', 'regression', 'mandatory', 'build'):
        e = evidence.get(name, {})
        if not result_ok(e) or e.get('revision') != current_revision or e.get('source_hash') != digest(FIXED):
            reasons.append(f'{name}: missing, failed or stale evidence')
    for name in ('recheck', 'mandatory'):
        e = evidence.get(name, {})
        checks = e.get('checks', {})
        if e.get('test_hash') != baseline.get('test_hash') or set(checks) != ALL_CHECKS or any(v is not True for v in checks.values()):
            reasons.append(f'{name}: original protected suite was not passed')
    if evidence.get('regression', {}).get('test_hash') != digest(REGRESSION):
        reasons.append('Regression suite changed')
    return {'status': 'FIXED' if not reasons else 'NEEDS_REVIEW', 'reasons': reasons,
            'scope': 'synthetic fixture only; scripted roles, no AI'}
