#!/usr/bin/env python3
"""Run saved histories; keep formal output separate from private diagnostics."""
from __future__ import annotations
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
import hashlib
import json

from fact_audit import (FactAuditError, audit_pair, audit_span, compile_ledger,
                        describe_problem, evaluate_rational_witness,
                        instantiate_pad_shift, poly_eval, verify_evidence, verify_history_extension)

HERE = Path(__file__).resolve().parent
COUNTS = {'histories': 0, 'stages': 0, 'assertions': 0, 'enumerated_family_pairs': 0}


def require(condition, description):
    COUNTS['assertions'] += 1
    if not condition:
        raise AssertionError(description)


def value_of_observation(problem, row, ordinary, pads, tau, is_point):
    p = problem.p
    ordinary_term = sum((poly_eval(c, tau, p) if is_point else c) * x
                        for c, x in zip(row['ordinary'], ordinary))
    pad_term = sum(c * x for c, x in zip(row['pads'], pads))
    if row['offset'] is None:
        return None
    offset = poly_eval(row['offset'], tau, p) if is_point else row['offset']
    return (ordinary_term + pad_term + offset) % p


def coefficient_model_check(problem, result, supplied):
    p, tau, beta = problem.p, supplied['tau'], supplied['beta']
    ordinary = [supplied['ordinary_values'][sid] % p for sid in problem.source_order]
    pads = [supplied['pad_values'][sid] % p for sid in problem.pad_order]
    out = {'observer_visible': False, 'evidence_level': 'EXPONENT_MODEL_IDENTITY_ONLY',
           'tau': tau, 'beta': beta, 'native_replay_verified': False}
    for row in problem.scalars:
        actual = value_of_observation(problem, row, ordinary, pads, tau, False)
        if actual is not None and row['rhs_available']:
            require(actual == row['rhs'], f'Fixture actual RHS mismatch: {row["observation_id"]}')
    if result['formal_status'] == 'COMPATIBLE':
        shift = instantiate_pad_shift(problem, result, tau, beta)
        displacements = [sum(a * d for a, d in zip(row, result['difference'])) % p for row in problem.A]
        shifted_w = [(w + beta * a * pow((tau - s['node']) % p, -1, p)) % p
                     for w, a, s in zip(ordinary, displacements, problem.sources)]
        shifted_r = [(r + delta) % p for r, delta in zip(pads, shift)]
        rows = []
        for is_point, observations in ((False, problem.scalars), (True, problem.points)):
            for row in observations:
                before = value_of_observation(problem, row, ordinary, pads, tau, is_point)
                after = value_of_observation(problem, row, shifted_w, shifted_r, tau, is_point)
                if before is not None:
                    require(before == after, 'Returned pad shift does not preserve an original observation')
                rows.append({'observation_id': row['observation_id'], 'before': before, 'after': after,
                             'numerical_offset_known_in_fixture': before is not None})
        out.update(pad_shift=shift, shifted_source_values=shifted_w, shifted_pad_values=shifted_r,
                   original_observation_comparisons=rows)
    else:
        out['rational_evaluation'] = evaluate_rational_witness(problem, result, tau, beta)
        w = result['witness']
        if not w['representation_prerequisites_present']:
            out['recipe_check'] = {'status': 'NOT_EXECUTED', 'reason': 'The returned witness lacks an observer representation prerequisite'}
            return out
        point_values = [value_of_observation(problem, row, ordinary, pads, tau, True) for row in problem.points]
        Cstar = (sum(c * v for c, v in zip(w['zeta'], point_values)) +
                 poly_eval(w['known_h_correction_polynomial'], tau, p)) % p
        f_values = [poly_eval(f, tau, p) for f in w['f_polynomials']]
        expected_Cstar = sum(f * x for f, x in zip(f_values, ordinary)) % p
        require(Cstar == expected_Cstar, 'Joint affine correction does not reconstruct f(tau)*w')
        y0 = result['y0']
        E_exponents = [(x - beta * sum(a * y for a, y in zip(row, y0)) *
                        pow((tau - source['node']) % p, -1, p)) % p
                       for x, row, source in zip(ordinary, problem.A, problem.sources)]
        test_value = (Cstar - sum(e * f for e, f in zip(E_exponents, f_values))) % p
        predictions = []
        for y in (result['y0'], result['y1']):
            prediction = sum(beta * sum(a * fact for a, fact in zip(row, y)) *
                             pow((tau - source['node']) % p, -1, p) * f
                             for row, source, f in zip(problem.A, problem.sources, f_values)) % p
            predictions.append(prediction)
        require(test_value == predictions[0], 'Test does not match the actually instantiated y0 world')
        require((predictions[1] - predictions[0]) % p == out['rational_evaluation']['rational_difference_value'],
                'Prediction difference disagrees with the formal rational witness')
        out['recipe_check'] = {'status': 'EXPONENT_MODEL_IDENTITY_ONLY', 'Cstar_exponent_relative_to_h': Cstar,
                               'test_exponent_relative_to_e_g_h': test_value,
                               'prediction_exponents': predictions,
                               'distinguishes_at_fixed_tau': predictions[0] != predictions[1],
                               'native_replay_verified': False}
    return out


def run():
    fixture_path = HERE / 'fixtures.json'
    source = json.loads(fixture_path.read_text())
    histories = []
    for history in source['histories']:
        stages = []
        previous = None
        COUNTS['histories'] += 1
        for stage in history['stages']:
            COUNTS['stages'] += 1
            if stage.get('expected_error'):
                try:
                    compile_ledger(stage['ledger'])
                except FactAuditError as exc:
                    require(stage['expected_error'] in str(exc), 'Unexpected model-contract error')
                    stages.append({'stage_id': stage['stage_id'], 'status': 'UNSUPPORTED_MODEL_REJECTED', 'error': str(exc)})
                    continue
                raise AssertionError('Unsupported world-dependent affine offset was accepted')
            problem = compile_ledger(stage['ledger'])
            extension = None
            if previous is not None:
                extension = verify_history_extension(previous, problem)
                require(extension['verified'], 'History did not preserve its original source bindings and visible ledger')
            previous = problem
            query = stage['query']
            if query['kind'] == 'pair':
                result = audit_pair(problem, query['y0'], query['y1'], query['pair_contract'])
            else:
                result = audit_span(problem, query['difference_vectors'], query['span_relation'], query.get('actual_pairs'))
            require(result['formal_status'] == stage['expected']['formal_status'], 'Unexpected formal compatibility status')
            require(result['execution_status'] == stage['expected']['execution_status'], 'Unexpected execution prerequisite status')
            require(verify_evidence(problem, result), 'Independent evidence verification failed')
            require(result['native_replay_verified'] is False, 'Coefficient evidence was upgraded to native replay')
            if 'expected_family_status' in stage:
                require(result['family_status'] == stage['expected_family_status'], 'Incorrect family/superset interpretation')
            if 'expected_history_contract_eligible' in stage:
                require(result['history_contract_eligible'] == stage['expected_history_contract_eligible'], 'Private-descriptor scope was lost')
            if stage.get('require_zero_residues'):
                require(all(x['value'] == 0 for x in result['witness']['rational_difference']['residues']), 'Residue separation fixture has a residue')
            if stage.get('require_nonzero_quotient'):
                require(any(result['witness']['rational_difference']['polynomial']), 'Missing quotient-only witness')
            if stage.get('require_mixed_witness'):
                require(any(result['witness']['c']) and all(result['witness']['zeta']), 'The mixed fixture failed to use the joint scalar/point system')
            if query['kind'] == 'pair':
                model = coefficient_model_check(problem, result, history['fixture_private_diagnostics'])
                if 'expected_fixed_tau_collision' in stage:
                    require(model['rational_evaluation']['fixed_tau_collision'] == stage['expected_fixed_tau_collision'], 'Fixed-tau collision was misreported')
                    model['alternate_tau_evaluation'] = evaluate_rational_witness(problem, result, stage['alternate_tau'], history['fixture_private_diagnostics']['beta'])
                    require(not model['alternate_tau_evaluation']['fixed_tau_collision'], 'Alternate admissible tau should separate the pair')
            else:
                family_checks = []
                for y0, y1 in combinations(query['family_assignments'], 2):
                    direct = audit_pair(problem, y0, y1, query['actual_pairs'][0]['pair_contract'])
                    COUNTS['enumerated_family_pairs'] += 1
                    require(direct['formal_status'] == 'COMPATIBLE', 'An actual legal family pair unexpectedly failed')
                    family_checks.append({'y0': y0, 'y1': y1, 'formal_status': direct['formal_status']})
                require(not result['actual_pair_failure_ids'], 'A conservative basis direction was misreported as an actual pair failure')
                model = {'observer_visible': False, 'enumerated_actual_family_pairs': family_checks,
                         'scope': 'All six pairs in the stated four-assignment synthetic family'}
            stages.append({'stage_id': stage['stage_id'], 'problem': describe_problem(problem),
                           'history_extension': extension,
                           'coefficient_evidence': result, 'auditor_private_diagnostics': model})
        histories.append({'history_id': history['history_id'], 'description': history['description'], 'stages': stages})
        print(f'PASS {history["history_id"]}: {len(stages)} stage(s)')
    result = {'schema': 'CHARE_FACT_FIXTURE_RUN_V1', 'generated_at_utc': datetime.now(timezone.utc).isoformat(),
              'all_passed': True, 'counts': COUNTS, 'histories': histories,
              'scope': 'Finite-field source coefficients and separately labeled synthetic exponent-model diagnostics',
              'native_replay_verified': False, 'original_artifact_checks': False,
              'fixtures_sha256': hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
              'solver_sha256': hashlib.sha256((HERE / 'fact_audit.py').read_bytes()).hexdigest()}
    destination = HERE / 'results' / 'fixtures_run.json'
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(f'PASS: {COUNTS["histories"]} histories / {COUNTS["stages"]} stages / {COUNTS["assertions"]} assertions')


if __name__ == '__main__':
    run()
