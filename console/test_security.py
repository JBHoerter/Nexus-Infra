"""Security boundary regression tests; no deployed service or credentials required."""
import io
import json
import os
from email.message import Message
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from agent import Agent, authorize_action
from common import Handler, HTTPError
from server import Console

INVENTORY = {'id':'host-a','vms':[{'id':'workload','controllable':True},{'id':'console','controllable':False}]}

class BoundaryTests(unittest.TestCase):
    def reject(self, status, callback, *args):
        with self.assertRaises(HTTPError) as caught:
            callback(*args)
        self.assertEqual(caught.exception.status, status)

    def test_actions_are_explicit(self):
        for action in ('start','stop','restart'):
            self.assertEqual(authorize_action(INVENTORY,'workload',{'action':action}), (action,'microvm@workload.service'))
        for payload in ({'action':'restart; touch /tmp/injected'}, {'action':['restart']}, {'action':'restart','command':'id'}, {}):
            self.reject(400,authorize_action,INVENTORY,'workload',payload)
        self.reject(403,authorize_action,INVENTORY,'console',{'action':'stop'})
        self.reject(404,authorize_action,INVENTORY,'workload/../../sshd',{'action':'restart'})

    @patch('agent.subprocess.run')
    def test_mutations_have_no_shell_and_are_rate_limited(self, run):
        agent=Agent({'inventory':INVENTORY})
        agent.action('workload',{'action':'restart'})
        self.assertEqual(run.call_args.args[0],['systemctl','--no-ask-password','--no-block','restart','microvm@workload.service'])
        self.assertNotIn('shell',run.call_args.kwargs)
        self.reject(429,agent.action,'workload',{'action':'stop'})
        self.assertEqual(run.call_count,1)

    def test_http_body_limits_and_shape(self):
        handler=object.__new__(Handler)
        for raw in (b'[]',b'{"action":"restart","command":"id"}',b'{"action":'):
            handler.headers=Message();handler.headers['Content-Type']='application/json';handler.headers['Content-Length']=str(len(raw));handler.rfile=io.BytesIO(raw)
            self.reject(400,handler.body,['action'],128)
        handler.headers['Transfer-Encoding']='chunked'
        self.reject(415,handler.body,['action'],128)
        del handler.headers['Transfer-Encoding'];del handler.headers['Content-Length'];handler.headers['Content-Length']='99999'
        self.reject(400,handler.body,['action'],128)

    @patch('server.ssl.create_default_context')
    @patch.dict(os.environ,{'CREDENTIALS_DIRECTORY':'/not-used'})
    def test_auth_session_expiry_offline_inventory_and_persistence(self, tls):
        with tempfile.TemporaryDirectory() as directory:
            config={'clusterName':'test','hosts':[{'inventory':INVENTORY,'agentUrl':'https://invalid'}]}
            console=Console(config,directory)
            password=(Path(directory)/'initial-password').read_text().strip()
            self.assertNotIn(password,(Path(directory)/'auth.json').read_text())
            self.reject(401,console.login,'incorrect')
            token,csrf=console.login(password)
            _,session=console.session('nexus_session='+token)
            self.assertEqual(session['csrf'],csrf)
            console.sessions[token]['created']-=30000
            self.reject(401,console.session,'nexus_session='+token)
            host=console.state()['hosts'][0]
            self.assertFalse(host['online']);self.assertTrue(host['stale']);self.assertEqual(host['inventory'],INVENTORY)
            second=Console(config,directory)
            second.login(password)
            for _ in range(8):self.reject(401,second.login,'bad')
            self.reject(429,second.login,password)

if __name__=='__main__':unittest.main()
