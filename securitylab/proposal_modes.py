"""Dispatch sealed fixture and S7.2 proposal contracts without broadening either."""
from . import ai_contract, access_contract, package_contract, discovery_contract, review_contract, research_contract
from .policy import PolicyError

_RESEARCH_TASKS = (research_contract.TASK_RED, research_contract.TASK_BLUE)


def _access(req):
    return isinstance(req, dict) and req.get('task') in (
        access_contract.TASK, package_contract.TASK, discovery_contract.TASK, review_contract.TASK,
        *_RESEARCH_TASKS)


def contract(req):
    if req.get("task") == review_contract.TASK: return review_contract
    if req.get("task") == discovery_contract.TASK: return discovery_contract
    if req.get("task") == research_contract.TASK_RED: return research_contract
    if req.get("task") == research_contract.TASK_BLUE: return research_contract
    return package_contract if req.get("task")==package_contract.TASK else access_contract

def proposal_prompt(req):
    if req.get('task') == research_contract.TASK_BLUE:
        return research_contract.blue_prompt(req)
    return contract(req).prompt(req) if _access(req) else ai_contract.prompt(req)


def proposal_validate(req, reply):
    if req.get('task') == research_contract.TASK_BLUE:
        return research_contract.validate_blue_reply(req, reply)
    if _access(req):
        return contract(req).validate_reply(req, reply)
    return ai_contract.validate_proposal(req['role'], reply,
            candidate=req.get('verification')=='actual-candidate-v1')


def proposal_system(req):
    if req.get('task') == research_contract.TASK_BLUE:
        return research_contract.blue_response_system(req['role'])
    return contract(req).response_system(req['role']) if _access(req) else ai_contract.response_system(req['role'])


def proposal_feedback(req, value):
    if req.get('task') == research_contract.TASK_BLUE:
        return research_contract.blue_feedback(req, value)
    return contract(req).feedback(req, value) if _access(req) else ai_contract.blue_feedback(
        value, candidate=req.get('verification')=='actual-candidate-v1')


def proposal_retry(req, previous):
    if req.get('task')==review_contract.TASK:
        if 'retry' in req: raise PolicyError('Review corrective attempt exhausted')
        result=dict(req,retry=previous); review_contract.validate_request(result); return result
    if req.get('task') == discovery_contract.TASK:
        if 'retry' in req: raise PolicyError('Discovery corrective attempt exhausted')
        retry=dict(req,retry=previous)
        discovery_contract.validate_request(retry)
        return retry
    if req.get('task') in _RESEARCH_TASKS:
        return research_contract.retry_request(req, previous)
    if _access(req):
        if req['role']!='blue' or 'retry' in req:
            raise PolicyError('S7.2 corrective attempt not allowed')
        return contract(req).make_request('blue', req['entry'], req['source'], req['checks'],
                   finding=req['finding'], retry=previous, **({'files':req['files']} if 'files' in req else {}))
    return ai_contract.request('blue', req['finding'], previous,
                   candidate=req.get('verification')=='actual-candidate-v1')
