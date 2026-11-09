"""S5 bounded fixture language, not a sandbox for arbitrary Python.

No calls except the built-in fixture dictionary's get, no attribute inspection,
no mutation of containers, no imports, output, exception handling or loops.
The module can compute wrong results: correctness belongs to the verifier.
"""
import ast
from .fixture import VULNERABLE
from .policy import PolicyError


def validate_candidate(source):
    if not isinstance(source, str) or len(source.encode('utf-8')) > 12000:
        raise PolicyError('Invalid candidate size')
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise PolicyError('Invalid candidate Python') from exc
    original = ast.parse(VULNERABLE)
    dump = lambda x: ast.dump(x, include_attributes=False)
    if (len(tree.body) != 2 or dump(tree.body[0]) != dump(original.body[0])
        or not isinstance(tree.body[1], ast.FunctionDef)):
        raise PolicyError('S5 requires unchanged RECORDS and one read_record function')
    fn = tree.body[1]
    if (fn.name != 'read_record' or dump(fn.args) != dump(original.body[1].args)
        or fn.decorator_list or fn.returns or fn.type_comment or getattr(fn, 'type_params', [])):
        raise PolicyError('S5 function signature cannot change')
    nodes = list(ast.walk(fn))
    if len(nodes) > 300:
        raise PolicyError('S5 candidate too complex')
    allowed = (ast.FunctionDef, ast.arguments, ast.arg, ast.Assign, ast.If, ast.Return,
               ast.Name, ast.Load, ast.Store, ast.Constant, ast.Subscript, ast.Tuple,
               ast.Compare, ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.BoolOp,
               ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Call, ast.Attribute)
    names = {'RECORDS', 'user', 'record_id', 'record', 'owner'}
    get_call = dump(ast.parse('RECORDS.get(record_id)', mode='eval').body)
    for node in nodes:
        if not isinstance(node, allowed):
            raise PolicyError('S5 operation forbidden: ' + type(node).__name__)
        if isinstance(node, ast.Name) and node.id not in names:
            raise PolicyError('S5 unknown name')
        if isinstance(node, ast.Assign) and (len(node.targets) != 1
            or not isinstance(node.targets[0], ast.Name) or node.targets[0].id not in {'record', 'owner'}
            or node.type_comment):
            raise PolicyError('S5 only local record/owner assignments allowed')
        if isinstance(node, ast.Call) and dump(node) != get_call:
            raise PolicyError('S5 only RECORDS.get(record_id) call allowed')
        if isinstance(node, ast.Attribute) and (node.attr != 'get'
            or not isinstance(node.value, ast.Name) or node.value.id != 'RECORDS'):
            raise PolicyError('S5 attribute access forbidden')
        # get may appear only as the callee, never as a returned callable.
        if isinstance(node, ast.Attribute) and not any(isinstance(p, ast.Call) and p.func is node for p in nodes):
            raise PolicyError('S5 bare method reference forbidden')
        if isinstance(node, ast.Constant) and type(node.value) not in (str, int, bool, type(None)):
            raise PolicyError('S5 constant forbidden')
    return source
