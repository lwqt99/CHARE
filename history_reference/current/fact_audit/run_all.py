#!/usr/bin/env python3
"""Run only the new fact-audit increment, using the pinned previous package."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prior-root', help='Extracted previous-increment root; alternatively set CHARE_R2_ROOT')
    args = parser.parse_args()
    if args.prior_root:
        os.environ['CHARE_R2_ROOT'] = str(Path(args.prior_root).expanduser().resolve())
    sys.path.insert(0, str(HERE.parent))
    from prior_runtime import EXPECTED, locate_prior
    prior = locate_prior(args.prior_root)
    results = HERE / 'results'
    results.mkdir(exist_ok=True)
    runs = []
    for name in ('run_fixtures.py', 'test_fact_audit.py'):
        start = time.perf_counter()
        completed = subprocess.run([sys.executable, str(HERE / name)], cwd=HERE,
                                   capture_output=True, text=True, env=os.environ.copy())
        elapsed = time.perf_counter() - start
        log = results / (Path(name).stem + '.log')
        log.write_text(completed.stdout + '\n--- STDERR ---\n' + completed.stderr)
        runs.append({'script': name, 'script_sha256': sha(HERE / name),
                     'returncode': completed.returncode, 'elapsed_seconds': elapsed,
                     'raw_log': log.name})
        print(f'{"PASS" if completed.returncode == 0 else "FAIL"} {name}: {elapsed:.3f}s; {log.name}')
        if completed.returncode:
            print((completed.stdout + completed.stderr)[-5000:])
            raise SystemExit(completed.returncode)
    fixtures = json.loads((results / 'fixtures_run.json').read_text())
    tests = json.loads((results / 'test_summary.json').read_text())
    assert fixtures['all_passed'] and tests['all_passed']
    assert fixtures['solver_sha256'] == tests['solver_sha256'] == sha(HERE / 'fact_audit.py')
    assert fixtures['native_replay_verified'] is False
    counts = {**fixtures['counts'], 'unit_tests': tests['tests_run'],
              **tests['independent_enumeration_counts']}
    code_names = ['fact_audit.py', 'fixtures.json', 'make_fixtures.py',
                  'run_fixtures.py', 'test_fact_audit.py', 'run_all.py']
    summary = {'schema': 'CHARE_FACT_INCREMENT_RUN_V1',
               'generated_at_utc': datetime.now(timezone.utc).isoformat(),
               'all_passed': True, 'python_executable': sys.executable,
               'counts': counts, 'runs': runs,
               'files_sha256': {name: sha(HERE / name) for name in code_names},
               'bootstrap_sha256': sha(HERE.parent / 'prior_runtime.py'),
               'prior_root_used': str(prior), 'prior_dependency_hashes': EXPECTED,
               'scope': 'New finite-field qualification coefficient solver and independent enumeration only',
               'native_curve_replay_in_this_runner': False, 'original_native_artifact_checks': False,
               'original_reported_1704_checks': False,
               'integration_results': 'Separate round-3 root files; not counted as fact-audit unit or fixture checks'}
    (results / 'run_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'all_passed': True, 'counts': counts}, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
