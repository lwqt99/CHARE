"""Reference Python batch/incremental audit measurements, not Go/PBC timings."""
from pathlib import Path
from datetime import datetime, timezone
import copy
import gc
import hashlib
import json
import platform
import random
import statistics
import sys
import time
import tracemalloc
from auditor import (Problem, RowSpace, audit, IncrementalAudit, lagrange_gamma,
                     restored_increment, verify_audit, canonical_json)

BASE = Path(__file__).resolve().parent
P = 2305843009213693951  # 2^61-1, prime.
COHORT = 16


def retained_size(value, seen=None):
    """CPython object graph size, not RSS, allocator overhead, or serialized bytes."""
    if seen is None:
        seen = set()
    identity = id(value)
    if identity in seen:
        return 0
    seen.add(identity)
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(retained_size(k, seen) + retained_size(v, seen) for k, v in value.items())
    elif isinstance(value, (list, tuple, set, frozenset)):
        size += sum(retained_size(x, seen) for x in value)
    elif hasattr(value, '__dict__'):
        size += retained_size(vars(value), seen)
    return size


def inputs(H):
    rng = random.Random(2026111403)
    masks, seen = [], set()
    while len(masks) < H:
        mask = rng.randrange(1, 1 << COHORT)
        if mask not in seen:
            masks.append(mask)
            seen.add(mask)
    problems = []
    for index, mask in enumerate(masks):
        J = [i for i in range(COHORT) if mask >> i & 1]
        columns = tuple(tuple(int(i == j) for i in range(COHORT)) for j in J)
        gamma = tuple(lagrange_gamma([i+1 for i in J], P))
        problems.append(Problem(f'target:{index}', columns, (0,) * len(J), gamma,
                                tuple(f'v{i+1}' for i in range(COHORT)),
                                'recorded_eta', f'ORIGINAL_CONTEXT_DESCRIPTOR:{index}'))
    U = [[pow(i+1, degree, P) for i in range(COHORT)] for degree in range(4)]
    candidate = [pow(i+1, 4, P) for i in range(COHORT)]
    new = RowSpace(U + [candidate], COHORT, P).rows
    R = restored_increment(U, new, COHORT, P)
    return problems, U, new, R


def run_batch(problems, new):
    return [audit(problem, new, P) for problem in problems]


def run_incremental(states, increment):
    return [state.append(increment) for state in states]


def audit_results(problems, new, results):
    if len(results) != len(problems):
        raise RuntimeError('Result count differs')
    for problem, result in zip(problems, results):
        if result['status'] != 'PROTECTED':
            raise RuntimeError('Safe-moment benchmark unexpectedly failed')
        verify_audit(problem, new, result, P)


def peak_run(function):
    gc.collect()
    tracemalloc.start()
    result = function()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, {'current_traced_bytes_after_audit': current, 'peak_traced_bytes_during_audit': peak}


def cpu_model():
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                return line.split(':', 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def measure(H):
    problems, U, new, R = inputs(H)
    trials = []
    final_batch = final_incremental = None
    last_states = None
    for trial in range(3):
        started = time.perf_counter_ns()
        states = [IncrementalAudit(problem, U, P) for problem in problems]
        preparation_ns = time.perf_counter_ns() - started
        started = time.perf_counter_ns()
        batch = run_batch(problems, new)
        batch_ns = time.perf_counter_ns() - started
        started = time.perf_counter_ns()
        incremental = run_incremental(states, R)
        incremental_ns = time.perf_counter_ns() - started
        audit_results(problems, new, batch)
        audit_results(problems, new, incremental)
        if [x['status'] for x in batch] != [x['status'] for x in incremental]:
            raise RuntimeError('Batch/incremental semantic mismatch')
        trials.append({'trial': trial, 'state_preparation_ns': preparation_ns,
                       'batch_audit_ns': batch_ns, 'incremental_audit_ns': incremental_ns,
                       'semantic_match': True, 'protected_targets': H})
        final_batch, final_incremental, last_states = batch, incremental, states
    batch_result, batch_memory = peak_run(lambda: run_batch(problems, new))
    memory_states = [IncrementalAudit(problem, U, P) for problem in problems]
    before_state_bytes = retained_size(memory_states)
    inc_result, inc_memory = peak_run(lambda: run_incremental(memory_states, R))
    audit_results(problems, new, batch_result)
    audit_results(problems, new, inc_result)
    certificate_payload = [{'target_id': x['target_id'], 'z': x['z'], 'a': x['a']} for x in final_incremental]
    fields = ('state_preparation_ns', 'batch_audit_ns', 'incremental_audit_ns')
    summary = {field: {'median': statistics.median(t[field] for t in trials),
                       'min': min(t[field] for t in trials), 'max': max(t[field] for t in trials)} for field in fields}
    return {'H': H, 'cohort': COHORT, 'ordinary_source_count': COHORT, 'pad_count': 0,
            'point_observations_before': 4, 'point_observations_after': 5,
            'capability_rank_before': 4, 'capability_rank_after': 5, 'full_increment_rank': len(R),
            'completed_plans': 0, 'pending_plans': 0,
            'target_slot_counts': [problem.slots for problem in problems],
            'trials': trials, 'timing_summary_ns': summary,
            'batch_memory': batch_memory,
            'incremental_memory': {**inc_memory, 'retained_state_object_bytes_before': before_state_bytes,
                                   'retained_state_object_bytes_after': retained_size(memory_states)},
            'shared_problem_object_bytes': retained_size(problems),
            'certificate_payload_json_bytes': len(canonical_json(certificate_payload).encode()),
            'witness_payload_json_bytes': 0, 'all_protected': True, 'batch_incremental_match': True,
            'certificate_sample_first': certificate_payload[0],
            'workload_sha256': hashlib.sha256(canonical_json({'target_ids': [x.target_id for x in problems],
                                    'columns': [x.columns for x in problems], 'gamma': [x.gamma for x in problems],
                                    'U': U, 'new': new}).encode()).hexdigest()}


def main():
    results = []
    for H in (1, 16, 64, 256):
        result = measure(H)
        results.append(result)
        b = result['timing_summary_ns']['batch_audit_ns']['median'] / 1e6
        i = result['timing_summary_ns']['incremental_audit_ns']['median'] / 1e6
        print(f'H={H}: batch median {b:.3f} ms; incremental median {i:.3f} ms; semantic match', flush=True)
    data = {'schema': 'CHARE_PYTHON_REFERENCE_AUDIT_BENCHMARK_V1',
            'generated_at_utc': datetime.now(timezone.utc).isoformat(),
            'environment': {'python': sys.version, 'platform': platform.platform(), 'machine': platform.machine(),
                            'cpu_model': cpu_model(), 'logical_cpu_count': __import__('os').cpu_count()},
            'field_prime': P, 'trial_count': 3,
            'timing_scope': 'Target coefficient audit after the capability basis is restored. Incremental states are prepared before each trial and their preparation time is reported separately. Timings do not include traced-memory profiling.',
            'memory_scope': 'One separate tracemalloc diagnostic pass per algorithm/configuration. Peak traced Python allocations exclude pre-existing retained states; those states are separately measured by recursive sys.getsizeof. Neither is process RSS.',
            'comparison_scope': 'Batch rebuilds each target certificate from full capability; incremental consumes the same full restored increment using preinitialized V/W and certificate state. Source restoration and network/cryptographic operations are outside this benchmark.',
            'native_Go_PBC': False, 'native_curve_or_KDF_replay': False,
            'original_reported_1704_checks': False,
            'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'auditor_sha256': hashlib.sha256((BASE / 'auditor.py').read_bytes()).hexdigest(),
            'results': results}
    (BASE / 'results' / 'benchmark_raw.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
