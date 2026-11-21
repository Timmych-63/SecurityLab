"""Static FastAPI inventory: never imports or executes target code on the host."""
import ast
import sys
from .package_contract import validate_files
from .policy import PolicyError


def inventory(files, entry):
    validate_files(files)
    modules={p[:-3].replace('/','.') if not p.endswith('/__init__.py') else p[:-12].replace('/','.') for p in files}
    rows=[]; dependencies=set(); unsupported=set(); routes=[]
    for path,source in sorted(files.items()):
        tree=ast.parse(source); imports=[]; functions=[]
        for node in ast.walk(tree):
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                names=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or '']
                for name in names:
                    imports.append(name)
                    if isinstance(node,ast.ImportFrom) and node.level: continue
                    top=name.split('.')[0]
                    if top and top not in sys.stdlib_module_names and top not in {m.split('.')[0] for m in modules}:
                        dependencies.add(top)
                        if top not in {'fastapi','pydantic','starlette','uvicorn','typing_extensions'}: unsupported.add(top)
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                functions.append({'name':node.name,'line':node.lineno,'parameters':[a.arg for a in node.args.args],
                                  'calls':sorted({ast.unparse(c.func) for c in ast.walk(node) if isinstance(c,ast.Call)})[:24]})
                for dec in node.decorator_list:
                    if isinstance(dec,ast.Call) and isinstance(dec.func,ast.Attribute) and dec.func.attr in {'get','post','put','patch','delete','head','options'}:
                        if not dec.args or not isinstance(dec.args[0],ast.Constant) or not isinstance(dec.args[0].value,str):
                            raise PolicyError('Dynamic route declarations require a different application profile')
                        routes.append({'method':dec.func.attr.upper(),'path':dec.args[0].value,'file':path,'handler':node.name,'line':node.lineno})
            # Prefix resolution and dynamic route registration are not guessed.
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in {'include_router','add_api_route','mount'}:
                raise PolicyError('Router mounting/dynamic registration is not supported by this first research profile')
        rows.append({'file':path,'lines':len(source.splitlines()),'imports':sorted(set(imports)),'functions':functions})
    if unsupported: raise PolicyError('Dependencies are not in the pinned FastAPI image: '+', '.join(sorted(unsupported)))
    if not any(r['file']==entry for r in routes): raise PolicyError('No statically declared entry routes in selected FastAPI profile')
    return {'entry':entry,'files':rows,'routes':routes,'dependencies':sorted(dependencies),
            'runtime':'Pinned FastAPI image; in-memory seed data; fresh container per batch',
            'limitations':['Static declarations only; call names are not a complete call graph','No database/external services or repository installation scripts']}


def matches(template,path):
    a=template.strip('/').split('/');b=path.strip('/').split('/')
    return len(a)==len(b) and all(x==y or (x.startswith('{') and x.endswith('}') and y) for x,y in zip(a,b))


def check_resources(mapping,context):
    for resource in context['resources']:
        if not any(r['method']=='GET' and matches(r['path'],resource['path']) for r in mapping['routes']):
            raise PolicyError('Documented resource has no mapped GET handler: '+resource['path'])
