"""I7: measured release evidence cannot pass by omission or empty outcomes."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from benchmarks.utility_report import EvidenceError, evaluate, regression_upper, verify_traces
from lang.limits import MAX_WIRE_BYTES


class TestUtilityEvidence(unittest.TestCase):
    def fixture(self,count=100):
        protocol = dict(status='approved',benchmark='TEST FIXTURE ONLY',revision='a'*40,
                        model='fixture',settings='frozen',policy='frozen',adapter_revision='b'*40,
                        max_steps=20,max_loss=.05,min_baseline_success=.5,
                        tasks=[{'id':str(i),'seed':0} for i in range(count)])
        raw = json.dumps(protocol).encode()
        result = {'protocol_sha256':sha256(raw).hexdigest(),'protocol_commit':'e'*40,'kind':'real-agent','runs':[
            dict(id=str(i),seed=0,baseline_success=True,gated_success=True,
                 baseline_trace_sha256='c'*64,gated_trace_sha256='d'*64,
                 error=None,security_violations=0) for i in range(count)]}
        return raw,protocol,result

    def trace_fixture(self, root):
        raw, protocol, results = self.fixture(1)
        traces = {}
        for arm in ('baseline', 'gated'):
            trace = dict(version=1, protocol_sha256=results['protocol_sha256'],
                         adapter_revision=protocol['adapter_revision'], id='0', seed=0,
                         arm=arm, success=True, error=None, security_violations=0,
                         events=[dict(step=0,operation='finish',status='ALLOW',
                                      input_sha256='a'*64,output_sha256='b'*64)])
            self.save_trace(root, results, arm, trace)
            traces[arm] = trace
        return raw, protocol, results, traces

    def save_trace(self, root, results, arm, trace):
        data=json.dumps(trace).encode(); digest=sha256(data).hexdigest()
        (root/(digest+'.json')).write_bytes(data)
        results['runs'][0][arm+'_trace_sha256']=digest

    def test_retained_trace_bytes_and_headers_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw, protocol, results, traces=self.trace_fixture(root)
            verify_traces(raw,protocol,results,root)
            for field, value in [('id','other'),('seed',True),('arm','gated'),
                                 ('success',False),('protocol_sha256','c'*64),
                                 ('adapter_revision','d'*40),('version',True),
                                 ('error','timeout'),('security_violations',False)]:
                trace=deepcopy(traces['baseline']); trace[field]=value
                self.save_trace(root,results,'baseline',trace)
                with self.subTest(field=field), self.assertRaises(EvidenceError):
                    verify_traces(raw,protocol,results,root)
            for event in ({},dict(traces['baseline']['events'][0],step=1),
                          dict(traces['baseline']['events'][0],operation='unfinished'),
                          dict(traces['baseline']['events'][0],status='UNKNOWN')):
                trace=deepcopy(traces['baseline']);trace['events']=[event]
                self.save_trace(root,results,'baseline',trace)
                with self.assertRaises(EvidenceError): verify_traces(raw,protocol,results,root)

    def test_missing_tampered_oversized_symlink_and_reused_trace_refused(self):
        for mode in ('missing','tampered','oversized','symlink','reused'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);raw,protocol,results,_=self.trace_fixture(root)
                path=root/(results['runs'][0]['baseline_trace_sha256']+'.json')
                if mode=='missing': path.unlink()
                elif mode=='tampered': path.write_bytes(path.read_bytes()+b' ')
                elif mode=='oversized': path.write_bytes(b' '*(MAX_WIRE_BYTES+1))
                elif mode=='symlink':
                    target=root/'target';path.rename(target);path.symlink_to(target)
                else:
                    results['runs'][0]['baseline_trace_sha256']=results['runs'][0]['gated_trace_sha256']
                with self.assertRaises((EvidenceError,OSError)):
                    verify_traces(raw,protocol,results,root)

    def test_complete_controls_and_exact_zero_loss_bound(self):
        self.assertTrue(evaluate(*self.fixture())['pass'])
        self.assertAlmostEqual(regression_upper(0,100),1-.05**.01)
        self.assertAlmostEqual(regression_upper(0,1),.95)
        self.assertEqual(regression_upper(100,100),1)
        self.assertGreater(regression_upper(5,100),.05)

    def test_empty_small_or_poor_baseline_cannot_pass(self):
        with self.assertRaises(EvidenceError):
            evaluate(*self.fixture(0))
        self.assertFalse(evaluate(*self.fixture(1))['pass'])
        raw,protocol,result = self.fixture()
        for run in result['runs']:
            run['baseline_success']=run['gated_success']=False
        self.assertFalse(evaluate(raw,protocol,result)['pass'])

    def test_missing_duplicate_unapproved_and_wrong_protocol_refused(self):
        raw,protocol,result = self.fixture()
        malformed = deepcopy(result); malformed['runs'].pop()
        with self.assertRaises(EvidenceError): evaluate(raw,protocol,malformed)
        malformed = deepcopy(result); malformed['runs'][-1]=malformed['runs'][0]
        with self.assertRaises(EvidenceError): evaluate(raw,protocol,malformed)
        with self.assertRaises(EvidenceError): evaluate(raw,dict(protocol,status='unapproved'),result)
        with self.assertRaises(EvidenceError): evaluate(raw+b' ',protocol,result)
        with self.assertRaises(EvidenceError): evaluate(raw,protocol,dict(result,kind='synthetic'))
        with self.assertRaises(EvidenceError): evaluate(raw,dict(protocol,max_loss=.99),result)

    def test_errors_violations_wrong_types_and_regressions_refused(self):
        for name,value in [('error','timeout'),('security_violations',1),
                           ('security_violations',False),('gated_success',1),
                           ('baseline_trace_sha256',''),('seed',True)]:
            raw,protocol,result=self.fixture(); result['runs'][0][name]=value
            with self.subTest(name=name), self.assertRaises(EvidenceError): evaluate(raw,protocol,result)
        raw,protocol,result=self.fixture()
        for run in result['runs'][:10]: run['gated_success']=False
        self.assertFalse(evaluate(raw,protocol,result)['pass'])
