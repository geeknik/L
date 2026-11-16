"""I6/I7/I8: actual subprocess boundaries, no fake transport success."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from gate.authority import Authority, TrustKey
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from gate.process import ModelProcess, ToolProcess
from lang.limits import MAX_SOURCE_BYTES


class TestProcessAdapter(unittest.TestCase):
    def test_huge_timeout_refuses_without_numeric_conversion_crash(self):
        with self.assertRaises(HostError) as caught:
            ModelProcess((sys.executable,), 10**10000)
        self.assertEqual(caught.exception.code, 'PROCESS.INVALID')

    def test_success_and_timeout_kill_same_group_descendants(self):
        for retain_pipes in (False, True):
            with self.subTest(retain_pipes=retain_pipes), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'delayed-effect'
                code = '''import os,sys,time,json
sys.stdin.read()
pid=os.fork()
if pid == 0:
    if not RETAIN:
        os.close(0); os.close(1); os.close(2)
    time.sleep(1)
    with open(TARGET,'w') as output: output.write('unexpected')
    os._exit(0)
print(json.dumps({'source':'ok'}),flush=True)
'''.replace('RETAIN',repr(retain_pipes)).replace('TARGET',repr(str(target)))
                adapter = self.model(code,.3)
                if retain_pipes:
                    with self.assertRaises(HostError) as caught:
                        adapter(())
                    self.assertEqual(caught.exception.code,'PROCESS.TIMEOUT')
                else:
                    self.assertEqual(adapter(()),'ok')
                time.sleep(1.1)
                self.assertFalse(target.exists())

    def model(self, code, timeout=2):
        return ModelProcess((sys.executable, '-c', code), timeout)

    def test_model_and_tool_protocol(self):
        model = self.model('import json,sys; x=json.load(sys.stdin); print(json.dumps({"source":x["inputs"][0]}))')
        self.assertEqual(model(('COMMIT example',)), 'COMMIT example')
        tool = ToolProcess((sys.executable, '-c',
            'import json,sys; x=json.load(sys.stdin); print(json.dumps({"result":str(x["arguments"]["count"])}))'))
        self.assertEqual(tool({'count': 12}), '12')

    def test_invalid_response_and_failure_are_sanitized(self):
        for response in ('{"source":"SECRET","source":"second"}', 'null',
                         '{"source":12}', '{"source":"SECRET","extra":1}',
                         '{"source":NaN}', '{}{}', '{"source":"\\ud800"}'):
            with self.subTest(response=response), self.assertRaises(HostError) as caught:
                self.model('import sys; sys.stdin.read(); print('+repr(response)+')')(())
            self.assertNotIn('SECRET', str(caught.exception))
        with self.assertRaises(HostError):
            self.model('import sys; sys.stdin.read(); sys.stdout.buffer.write(b"\\xff")')(())
        with self.assertRaises(HostError):
            self.model('import sys; sys.stdin.read(); print("SECRET",file=sys.stderr); sys.exit(2)')(())

    def test_blocked_stdin_and_closed_pipes_have_deadlines(self):
        for code in ('import time; time.sleep(20)',
                     'import os,time; os.close(0); os.close(1); os.close(2); time.sleep(20)'):
            start = time.monotonic()
            with self.assertRaises(HostError):
                self.model(code, .15)(('x'*30000,))
            self.assertLess(time.monotonic()-start, 3)

    def test_floods_cannot_deadlock_or_grow_output(self):
        for stream in ('stdout','stderr'):
            with self.assertRaises(HostError) as caught:
                self.model(f'import sys,time; sys.{stream}.write("x"*{MAX_SOURCE_BYTES+1}); sys.{stream}.flush(); time.sleep(20)')(())
            self.assertEqual(caught.exception.code, 'PROCESS.LIMIT')

    def test_write_before_read_and_minimal_environment(self):
        model = self.model('import json,os,sys; sys.stderr.write("x"*20000); sys.stderr.flush(); x=json.load(sys.stdin); print(json.dumps({"source":str(len(x["inputs"][0]))+":"+str("HOME" in os.environ)}))')
        self.assertEqual(model(('x'*30000,)), '30000:False')

    def test_input_and_configuration_limits(self):
        for argv, deadline in ((('python',),1), ((sys.executable,),0),
                               ((sys.executable,),float('nan')), ((sys.executable,),True)):
            with self.assertRaises(HostError):
                ModelProcess(argv, deadline)
        with self.assertRaises(HostError):
            self.model('raise RuntimeError')(('x'*(MAX_SOURCE_BYTES+1),))
        with self.assertRaises(HostError):
            ToolProcess((sys.executable,))({'bad':True})

    def test_signed_host_dispatch_and_denial_have_real_file_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'effect.txt'
            code = ('import json,sys; from pathlib import Path; x=json.load(sys.stdin); '
                    'Path(sys.argv[1]).write_text(x["arguments"]["value"]); print(json.dumps({"result":"saved"}))')
            tool = ToolRegistration('srv:writer', b'fixed test writer', 'public',
                                   ToolProcess((sys.executable,'-c',code,str(target))))
            authority = Authority()
            trust = TrustKey(authority.public_key, frozenset(('grant','endorse','revoke')),
                             frozenset(('fs.write',)), 'high')
            host = LocalHost({'issuer':trust}, [tool], model_clearance='public', clock=lambda:110)
            source = ('DIRECT cap:'+'a'*64+' (scope=fs.write, exp=60, from=issuer) call tool:'
                      '(srv:writer, sha256:'+tool.content_hash+') {value: "exact"}')
            model = self.model('import sys,json; sys.stdin.read(); print(json.dumps({"source":'+repr(source)+'}))')
            claims = dict(version=1,kind='grant',issuer='issuer',subject=host.subject,
                          capability='a'*64,scope='fs.write',tool_principal=tool.principal,
                          tool_hash=tool.content_hash,integrity='high',action_hash='',
                          issued_at=100,expires_at=200,nonce='1'*64)
            host.apply(authority.sign(claims))
            with self.assertRaises(HostError):
                host.run([LabeledInput('untrusted')],model)
            self.assertFalse(target.exists())
            host.apply(authority.sign(dict(claims,kind='endorse',nonce='2'*64,
                                           action_hash=sha256(source.encode()).hexdigest())))
            result = host.run([],model)
            self.assertEqual(result.text,'saved')
            self.assertEqual(target.read_text(),'exact')
            host.apply(authority.sign(dict(claims,kind='revoke',nonce='3'*64)))
            with self.assertRaises(HostError):
                host.run([],model)
            self.assertEqual(target.read_text(),'exact')
