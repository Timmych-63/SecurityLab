import json, sys, threading, argparse, os, tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
parser=argparse.ArgumentParser(description='Real Hermes API compatibility probe with a fake model; no inference')
parser.add_argument('--hermes-source',type=Path,required=True)
args=parser.parse_args()
probe_home=tempfile.TemporaryDirectory()
os.environ['HERMES_HOME']=probe_home.name
Path(probe_home.name,'config.yaml').write_text('model:\n  context_length: 64000\n  ollama_num_ctx: 64000\n',encoding='utf-8')
sys.path[:0]=[str(args.hermes_source.resolve()),str(Path(__file__).resolve().parents[1])]
from run_agent import AIAgent
from securitylab.hermes_worker import invoke
from securitylab.ai_contract import request
calls=[]
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        data={'object':'list','data':[{'id':'qwen3.5:2b','object':'model','context_length':64000}]}
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(data).encode())
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));calls.append((self.path,body.get('tools')))
        value={'id':'test','object':'chat.completion','model':'qwen3.5:2b','choices':[{'index':0,'message':{'role':'assistant','content':'{"ready":true}'},'finish_reason':'stop'}], 'usage':{'prompt_tokens':50,'completion_tokens':5,'total_tokens':55}}
        if body.get('stream'):
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
            value['object']='chat.completion.chunk';value['choices'][0]['delta']=value['choices'][0].pop('message')
            self.wfile.write(('data: '+json.dumps(value)+'\n\ndata: [DONE]\n\n').encode())
        else:
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(value).encode())
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
def factory(**kwargs):
    kwargs['base_url']=f'http://127.0.0.1:{server.server_port}/v1'
    return AIAgent(**kwargs)
try:
    result=invoke(request('smoke'),factory)
    assert result=={'ready':True}
    assert calls and all(not tools for _,tools in calls)
    print(json.dumps({'status':'PASS','real_hermes':True,'model_endpoint':'FAKE_HTTP','calls':calls,'result':result}))
finally:
    server.shutdown()
    probe_home.cleanup()
