"""I7: measured release evidence cannot pass by omission or empty outcomes."""
from copy import deepcopy
from hashlib import sha256
import json
import unittest
from benchmarks.utility_report import EvidenceError, evaluate, regression_upper


class TestUtilityEvidence(unittest.TestCase):
    def fixture(self,count=100):
        protocol = dict(status='approved',benchmark='TEST FIXTURE ONLY',revision='a'*40,
                        model='fixture',settings='frozen',policy='frozen',adapter_revision='b'*40,
                        max_steps=20,max_loss=.05,min_baseline_success=.5,
                        tasks=[{'id':str(i),'seed':0} for i in range(count)])
        raw = json.dumps(protocol).encode()
        result = {'protocol_sha256':sha256(raw).hexdigest(),'kind':'real-agent','runs':[
            dict(id=str(i),seed=0,baseline_success=True,gated_success=True,
                 baseline_trace_sha256='c'*64,gated_trace_sha256='d'*64,
                 error=None,security_violations=0) for i in range(count)]}
        return raw,protocol,result

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
