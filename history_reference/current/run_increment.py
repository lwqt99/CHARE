#!/usr/bin/env python3
"""Run this increment only, against the exact extracted prior package.

No network, package installation, manuscript mutation, or native-performance
claim is made. Results are regenerated in this increment's results folders.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prior-root', type=Path)
    args = parser.parse_args()
    if args.prior_root:
        os.environ['CHARE_R2_ROOT'] = str(args.prior_root.expanduser().resolve())
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    from prior_runtime import locate_prior, EXPECTED
    prior = locate_prior(args.prior_root)
    output = HERE / 'results'
    output.mkdir(exist_ok=True)
    scripts = ('fact_audit/run_all.py', 'affine_replay/run_checks.py',
               'fact_curve_replay.py', 'joint_guard.py',
               'proof_review/fact_conditions_checks.py', 'proof_review/fact_code_spotchecks.py')
    records = []
    for name in scripts:
        path = HERE / name
        completed = subprocess.run([sys.executable, str(path)], cwd=HERE,
                                   capture_output=True, text=True, env=os.environ.copy())
        logname = name.replace('/', '_').removesuffix('.py') + '.log'
        (output / logname).write_text(completed.stdout + '\n[stderr]\n' + completed.stderr)
        records.append({'script': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'returncode': completed.returncode, 'log': logname})
        print(('PASS ' if completed.returncode == 0 else 'FAIL ') + name)
        if completed.returncode:
            print((completed.stdout + completed.stderr)[-6000:])
            raise SystemExit(completed.returncode)
    summary = {'schema': 'CHARE_INCREMENT3_RUN', 'all_passed': True,
               'generated_at_utc': datetime.now(timezone.utc).isoformat(),
               'python_version': sys.version, 'prior_dependency_hashes': EXPECTED,
               'prior_root_used': str(prior), 'runs': records,
               'fact_counts': json.loads((HERE / 'fact_audit/results/run_summary.json').read_text())['counts'],
               'fact_curve_counts': json.loads((HERE / 'fact_curve/results.json').read_text())['counts'],
               'joint_guard_counts': json.loads((HERE / 'joint_guard_results.json').read_text())['counts'],
               'scope': 'Independent new formal/affine/tiny-curve reference checks only',
               'original_native_replay': False, 'latex_compile': False, 'native_performance_measurement': False}
    affine = json.loads((HERE / 'affine_replay/raw_results.json').read_text())
    summary['affine_results_file'] = 'affine_replay/raw_results.json'
    summary['affine_results_sha256'] = hashlib.sha256((HERE / 'affine_replay/raw_results.json').read_bytes()).hexdigest()
    (output / 'increment_run.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print('All increment-3 checks passed; see results/increment_run.json.')


if __name__ == '__main__':
    main()
