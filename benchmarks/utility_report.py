"""Validate frozen real-agent paired evidence; never infer success from no data."""
import argparse
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import sys
import stat
from typing import Any

from lang.limits import MAX_SECURITY_RECORDS, MAX_WIRE_BYTES


class EvidenceError(Exception):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError('Duplicate evidence field')
        result[key] = value
    return result


def read(path: Path) -> tuple[bytes, Any]:
    with path.open('rb') as stream:
        raw = stream.read(MAX_WIRE_BYTES + 1)
    if len(raw) > MAX_WIRE_BYTES:
        raise EvidenceError('Evidence exceeds limit')
    return raw, json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)


def _fields(value: Any, names: set[str]) -> None:
    if type(value) is not dict or set(value) != names:
        raise EvidenceError('Invalid evidence schema')


def _hash(value: Any, length: int = 64) -> bool:
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None


def regression_upper(losses: int, count: int) -> float:
    """One-sided 95% Clopper-Pearson bound, using a log-space binomial CDF."""
    if not 0 <= losses <= count or count < 1:
        raise EvidenceError('Invalid sample count')
    if losses == count:
        return 1.0
    if losses == 0:
        return -math.expm1(math.log(.05)/count)
    def cdf(p: float) -> float:
        terms = [math.lgamma(count+1)-math.lgamma(k+1)-math.lgamma(count-k+1)
                 + k*math.log(p)+(count-k)*math.log1p(-p)
                 for k in range(losses+1)]
        maximum = max(terms)
        return math.exp(maximum)*sum(math.exp(t-maximum) for t in terms)
    low, high = losses/count, 1.0
    for _ in range(60):
        middle = (low+high)/2
        if middle == 1:
            break
        if cdf(middle) > .05:
            low = middle
        else:
            high = middle
    return high


def evaluate(protocol_raw: bytes, protocol: Any, results: Any) -> dict[str, Any]:
    if type(protocol_raw) is not bytes or len(protocol_raw) > MAX_WIRE_BYTES:
        raise EvidenceError('Invalid protocol bytes')
    try:
        decoded = json.loads(protocol_raw.decode('utf-8'), object_pairs_hook=_pairs)
        if json.dumps(decoded,sort_keys=True,allow_nan=False) != json.dumps(protocol,sort_keys=True,allow_nan=False):
            raise EvidenceError('Protocol object does not match frozen bytes')
    except (ValueError,TypeError,UnicodeError,RecursionError):
        raise EvidenceError('Invalid protocol bytes') from None
    _fields(protocol, {'status','benchmark','revision','model','settings','policy',
                       'adapter_revision','max_steps','max_loss','min_baseline_success','tasks'})
    if protocol['status'] != 'approved':
        raise EvidenceError('Utility protocol has not been approved')
    for name in ('benchmark','model','settings','policy'):
        if type(protocol[name]) is not str or not protocol[name].strip():
            raise EvidenceError('Missing frozen configuration')
    if not _hash(protocol['revision'],40) or not _hash(protocol['adapter_revision'],40):
        raise EvidenceError('Missing exact revision')
    if type(protocol['max_steps']) is not int or not 1 <= protocol['max_steps'] <= MAX_SECURITY_RECORDS:
        raise EvidenceError('Invalid step budget')
    for name in ('max_loss','min_baseline_success'):
        value = protocol[name]
        if type(value) not in (int,float) or not math.isfinite(value) or not 0 < value < 1:
            raise EvidenceError('Invalid frozen threshold')
    tasks = protocol['tasks']
    if type(tasks) is not list or not 1 <= len(tasks) <= MAX_SECURITY_RECORDS:
        raise EvidenceError('Missing frozen task set')
    identities: dict[str,int] = {}
    for task in tasks:
        _fields(task, {'id','seed'})
        if (type(task['id']) is not str or not task['id'] or task['id'] in identities
                or type(task['seed']) is not int or not 0 <= task['seed'] <= 2147483647):
            raise EvidenceError('Invalid or repeated frozen task')
        identities[task['id']] = task['seed']
    _fields(results, {'protocol_sha256','protocol_commit','kind','runs'})
    if not _hash(results['protocol_commit'],40):
        raise EvidenceError('Missing protocol freeze commit')
    if results['protocol_sha256'] != sha256(protocol_raw).hexdigest() or results['kind'] != 'real-agent':
        raise EvidenceError('Evidence does not match frozen real-agent protocol')
    runs = results['runs']
    if type(runs) is not list or len(runs) != len(identities):
        raise EvidenceError('Incomplete paired evidence')
    seen: set[str] = set()
    baseline = gated = losses = 0
    for run in runs:
        _fields(run, {'id','seed','baseline_success','gated_success','baseline_trace_sha256',
                      'gated_trace_sha256','error','security_violations'})
        task_id = run['id']
        if (type(task_id) is not str or task_id not in identities or task_id in seen
                or type(run['seed']) is not int or run['seed'] != identities[task_id]):
            raise EvidenceError('Unexpected or repeated result')
        seen.add(task_id)
        if (type(run['baseline_success']) is not bool or type(run['gated_success']) is not bool
                or not _hash(run['baseline_trace_sha256']) or not _hash(run['gated_trace_sha256'])
                or run['error'] is not None or type(run['security_violations']) is not int
                or run['security_violations'] != 0):
            raise EvidenceError('Invalid or failed paired run')
        baseline += run['baseline_success']
        gated += run['gated_success']
        losses += run['baseline_success'] and not run['gated_success']
    count = len(runs)
    upper = regression_upper(losses,count)
    passed = baseline/count >= protocol['min_baseline_success'] and upper <= protocol['max_loss']
    return {'pass':passed, 'tasks':count, 'baseline_success':baseline/count,
            'gated_success':gated/count, 'observed_loss':(baseline-gated)/count,
            'regression_upper_95':upper, 'max_loss':protocol['max_loss']}


def verify_traces(protocol_raw: bytes, protocol: Any, results: Any, trace_root: Path) -> None:
    """Verify retained bytes and bindings, not producer honesty or real execution."""
    evaluate(protocol_raw, protocol, results)
    directory = os.open(trace_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for run in results['runs']:
            for arm in ('baseline', 'gated'):
                digest = run[arm+'_trace_sha256']
                descriptor = os.open(digest+'.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=directory)
                with os.fdopen(descriptor, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WIRE_BYTES:
                        raise EvidenceError('Invalid trace file')
                    raw = stream.read(MAX_WIRE_BYTES+1)
                if len(raw) > MAX_WIRE_BYTES or sha256(raw).hexdigest() != digest:
                    raise EvidenceError('Trace digest mismatch')
                trace = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
                _fields(trace, {'version','protocol_sha256','adapter_revision','id','seed','arm',
                                'success','error','security_violations','events'})
                if (type(trace['version']) is not int or trace['version'] != 1
                        or trace['protocol_sha256'] != results['protocol_sha256']
                        or trace['adapter_revision'] != protocol['adapter_revision']
                        or trace['id'] != run['id'] or type(trace['seed']) is not int
                        or trace['seed'] != run['seed'] or trace['arm'] != arm
                        or type(trace['success']) is not bool
                        or trace['success'] != run[arm+'_success']
                        or trace['error'] is not None or type(trace['security_violations']) is not int
                        or trace['security_violations'] != run['security_violations']):
                    raise EvidenceError('Trace metadata mismatch')
                events = trace['events']
                if type(events) is not list or not 1 <= len(events) <= MAX_SECURITY_RECORDS:
                    raise EvidenceError('Invalid trace events')
                for step, event in enumerate(events):
                    _fields(event, {'step','operation','status','input_sha256','output_sha256'})
                    if (type(event['step']) is not int or event['step'] != step
                            or type(event['operation']) is not str or not event['operation'].strip()
                            or event['status'] not in ('ALLOW','DENY','ERROR')
                            or not _hash(event['input_sha256']) or not _hash(event['output_sha256'])):
                        raise EvidenceError('Invalid trace event')
                if events[-1]['operation'] != 'finish':
                    raise EvidenceError('Missing final trace event')
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('protocol',type=Path)
    parser.add_argument('results',type=Path)
    parser.add_argument('--trace-root',type=Path,required=True)
    args = parser.parse_args()
    try:
        raw, protocol = read(args.protocol)
        _, results = read(args.results)
        report = evaluate(raw,protocol,results)
        verify_traces(raw,protocol,results,args.trace_root)
        print(json.dumps(report,sort_keys=True,allow_nan=False))
        return 0 if report['pass'] else 1
    except (EvidenceError,OSError,ValueError,TypeError,UnicodeError,RecursionError):
        print('Utility evidence is incomplete or invalid',file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
