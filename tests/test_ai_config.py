import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from securitylab.ai_config import AIConfig, from_dict, load_config
from securitylab.ai_contract import request
from securitylab.hermes_adapter import HermesAdapter, validate_envelope
from securitylab.hermes_worker import invoke
from securitylab.policy import PolicyError, Limits
from test_ai import Agent, DockerTransport, envelope

class ConfigurationTests(unittest.TestCase):
    def test_reject_invalid_and_unsupported(self):
        for value in [{'context_tokens':8192}, {'timeout_seconds':True}, {'timeout_seconds':1201},
                      {'max_output_tokens':5000}, {'server_url':'https://example.com'},
                      {'server_url':'http://model:11434/v1'}, {'tools':['shell']},
                      {'model':'other'}, {'model_digest':'a'*64},
                      {'frequency_penalty':2.5}, {'frequency_penalty':-0.1},
                      {'frequency_penalty':'high'}, {'presence_penalty':True},
                      {'presence_penalty':3}]:
            with self.subTest(value=value), self.assertRaises(PolicyError): from_dict(value)
        with self.assertRaises(PolicyError): Limits(timeout=1200)

    def test_generation_penalties_optional(self):
        self.assertIsNone(AIConfig().frequency_penalty)
        self.assertIsNone(AIConfig().presence_penalty)
        config = from_dict({'frequency_penalty': 0.3, 'presence_penalty': 1})
        self.assertEqual((config.frequency_penalty, config.presence_penalty), (0.3, 1))

    def test_penalties_reach_request_overrides_when_set(self):
        config = AIConfig(model='other:2b', model_digest='a'*64,
                          frequency_penalty=0.4, presence_penalty=0.2)
        class Fake(Agent):
            instances=[];tool_list=[];messages=[];reply='{"ready":true}'
        invoke(request('smoke'), Fake, config=config)
        kw = Fake.instances[-1].kwargs
        self.assertEqual(kw['request_overrides'],
                         {'temperature': 0, 'response_format': {'type': 'json_object'},
                          'frequency_penalty': 0.4, 'presence_penalty': 0.2})

    def test_penalties_absent_when_unset(self):
        config = AIConfig(model='other:2b', model_digest='a'*64)
        class Fake(Agent):
            instances=[];tool_list=[];messages=[];reply='{"ready":true}'
        invoke(request('smoke'), Fake, config=config)
        self.assertEqual(Fake.instances[-1].kwargs['request_overrides'],
                         {'temperature': 0, 'response_format': {'type': 'json_object'}})

    def test_explicit_file_no_silent_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ai.toml'
            with patch.dict(os.environ, {'SECURITYLAB_AI_CONFIG':str(p)}):
                with self.assertRaises(PolicyError):load_config()
                p.write_text('[ai]\ncontext_tokens = 8192\n')
                with self.assertRaises(PolicyError):load_config()
                p.write_text('[ai]\ntimeout_seconds = 600\n',encoding='utf-8-sig')
                self.assertEqual(load_config().timeout_seconds,600)

    def test_alternate_model_binding(self):
        config=AIConfig(model='other:2b',model_digest='a'*64)
        req=request('smoke'); value=envelope(req,{'ready':True})
        with self.assertRaises(PolicyError):validate_envelope(req,value,config)
        value.update(model=config.model,model_digest=config.model_digest)
        self.assertEqual(validate_envelope(req,value,config),{'ready':True})
        with self.assertRaises(PolicyError):validate_envelope(req,value)

    def test_worker_parameters_and_no_tools(self):
        config=AIConfig(model='other:2b',model_digest='a'*64, timeout_seconds=600,max_output_tokens=1024)
        class Fake(Agent):
            instances=[];tool_list=[];messages=[];reply='{"ready":true}'
        invoke(request('smoke'),Fake,config=config)
        kw=Fake.instances[-1].kwargs
        self.assertEqual((kw['model'],kw['run_budget_seconds'],kw['max_tokens']),('other:2b',540,1024))
        self.assertEqual(kw['enabled_toolsets'],[])

    def test_transport_captures_configuration_once(self):
        config=AIConfig(model='other:2b',model_digest='a'*64,timeout_seconds=600)
        class Fake(DockerTransport):
            def __call__(self,argv,cwd,limits,**kwargs):
                r=super().__call__(argv,cwd,limits,**kwargs)
                if 'start' in argv:
                    self.deadline=limits.timeout
                    v=json.loads(r.stdout);v.update(model=config.model,model_digest=config.model_digest)
                    r.stdout=json.dumps(v)
                return r
        with tempfile.TemporaryDirectory() as d:
            fake=Fake();a=HermesAdapter(d,Path(d)/'calls',fake,config=config)
            _,record=a.ask(request('smoke'))
            self.assertEqual(fake.deadline,600)
            self.assertEqual(record['ai_config_sha256'],config.sha256)
            create=next(c for c in fake.calls if 'create' in c)
            runtime=next(x for x in create if x.startswith('SECURITYLAB_AI_RUNTIME='))
            self.assertEqual(json.loads(runtime.split('=',1)[1]),config.data())
