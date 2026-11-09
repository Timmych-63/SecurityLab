"""Dispatch sealed fixture and S7.2 proposal contracts without broadening either."""
from . import ai_contract, access_contract
from .policy import PolicyError


def _access(req):
    return isinstance(req, dict) and req.get('task') == access_contract.TASK


def proposal_prompt(req):
    return access_contract.prompt(req) if _access(req) else ai_contract.prompt(req)


def proposal_validate(req, reply):
    if _access(req):
        return access_contract.validate_reply(req, reply)
    return ai_contract.validate_proposal(req['role'], reply,
            candidate=req.get('verification')=='actual-candidate-v1')


def proposal_system(req):
    return access_contract.response_system(req['role']) if _access(req) else ai_contract.response_system(req['role'])


def proposal_feedback(req, value):
    return access_contract.feedback(req, value) if _access(req) else ai_contract.blue_feedback(
        value, candidate=req.get('verification')=='actual-candidate-v1')


def proposal_retry(req, previous):
    if _access(req):
        if req['role']!='blue' or 'retry' in req:
            raise PolicyError('S7.2 corrective attempt not allowed')
        return access_contract.make_request('blue', req['entry'], req['source'], req['checks'],
                   finding=req['finding'], retry=previous)
    return ai_contract.request('blue', req['finding'], previous,
                   candidate=req.get('verification')=='actual-candidate-v1')
