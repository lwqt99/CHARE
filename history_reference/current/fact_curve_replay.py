#!/usr/bin/env python3
"""Execute qualification witnesses using only public tiny-curve inputs.

The executor has no setup trapdoor, source values, pad values, true-world bit,
or expected answer.  Fixture generation and compatible-world coupling below
are separate diagnostic operations.  The backend is the hash-pinned prior
increment's deliberately insecure E/F_523 subgroup of order 131.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path

from prior_runtime import load_pairing, load_replay
from fact_audit.fact_audit import (compile_ledger, audit_pair, verify_evidence,
                                   poly_eval, instantiate_pad_shift)

curve = load_pairing()
old = load_replay()
R = curve.R
HERE = Path(__file__).resolve().parent


def known_polynomial_point(pp, polynomial):
    if len(polynomial) > len(pp['T']):
        raise ValueError('Public power ladder is incomplete')
    return curve.linear_combination((c, old.point(pp['T'][k]))
                                    for k, c in enumerate(polynomial))


def validate_public_setup(pp, problem):
    body = {k: v for k, v in pp.items() if k != 'setup_id'}
    if hashlib.sha256(old.canonical_json(body)).hexdigest() != pp['setup_id']:
        raise ValueError('Public setup digest mismatch')
    if problem.setup_id != pp['setup_id'] or problem.p != R:
        raise ValueError('Ledger and public curve setup differ')
    if list(problem.setup_nodes) != list(range(1, pp['N'] + 1)):
        raise ValueError('This diagnostic requires the original sequential setup nodes')
    if len(pp['T']) != pp['N'] or pp['T'][0] != pp['h']:
        raise ValueError('Malformed public power ladder')
    for key in ('g', 'h'):
        if old.point(pp[key]) is None:
            raise ValueError('Public generators must be nonidentity')


def execute_fact_test(pp, ledger, evidence, public_view):
    """Compute the Proposition factattack test, without private diagnostics.

    A returned witness can be blocked although a different witness is usable.
    This executor validates the supplied recipe; it does not enumerate all
    possible observer computations or certify an application's pair contract.
    """
    problem = compile_ledger(ledger)
    verify_evidence(problem, evidence)
    validate_public_setup(pp, problem)
    if public_view.get('setup_id') != pp['setup_id'] or public_view.get('ledger_digest') != problem.ledger_digest:
        raise ValueError('Public view is bound to another setup or ledger')
    if evidence.get('query_kind') != 'fixed_pair':
        raise ValueError('An executable two-world test requires an actual fixed pair')
    if evidence['formal_status'] != 'INCOMPATIBLE':
        return {'status': 'NO_DISTINGUISHING_WITNESS', 'native_replay_verified': False}
    if evidence['execution_status'] != 'PAIRING_TEST_RECIPE_READY':
        return {'status': evidence['execution_status'], 'native_replay_verified': False,
                'actual_curve_test_executed': False}
    witness = evidence['witness']
    terms = []
    for term in witness['point_terms']:
        handle = term['handle_id']
        if handle not in public_view['point_handles']:
            raise ValueError('The required observed point handle is absent')
        terms.append((term['coefficient'], old.point(public_view['point_handles'][handle])))
    for term in witness['scalar_terms']:
        if public_view['scalar_answers'].get(term['observation_id']) != term['actual_rhs']:
            raise ValueError('The original scalar answer does not match the ledger')
    terms.append((1, known_polynomial_point(pp, witness['known_h_correction_polynomial'])))
    Cstar = curve.linear_combination(terms)
    observed = curve.pairing(old.point(pp['g']), Cstar)
    predictions = [curve.Fq2(1), curve.Fq2(1)]
    f_points = []
    for source, polynomial in zip(problem.sources, witness['f_polynomials']):
        if not any(polynomial):
            continue
        handle = source['canonical_point']['handle_id']
        record = public_view['canonical_records'].get(handle)
        if record is None or record['source_id'] != source['source_id']:
            raise ValueError('Missing or rebound canonical source point')
        E = old.point(record['E'])
        if len(record['projections']) != pp['N'] - 1:
            raise ValueError('Incomplete canonical projection ladder')
        for k, projection in enumerate(record['projections']):
            base = curve.linear_combination([(1, old.point(pp['T'][k + 1])),
                                               (-source['node'], old.point(pp['T'][k]))])
            if curve.pairing(E, base) != curve.pairing(old.point(pp['g']), old.point(projection)):
                raise ValueError('Canonical projection equality failed')
        fp = known_polynomial_point(pp, polynomial)
        observed = observed / curve.pairing(E, fp)
        slot_base = curve.pairing(old.point(pp['W'][str(source['node'])]), fp)
        for b, y in enumerate((evidence['y0'], evidence['y1'])):
            fact = sum(a * v for a, v in zip(source['fact_map'], y)) % R
            predictions[b] = predictions[b] * (slot_base ** fact)
        f_points.append({'source_id': source['source_id'], 'f_h': old.point_hex(fp)})
    matches = [b for b, predicted in enumerate(predictions) if observed == predicted]
    if predictions[0] == predictions[1]:
        status = 'SETUP_COLLISION_INCONCLUSIVE' if matches else 'REPLAY_MISMATCH'
    else:
        status = f'MATCHES_WORLD_{matches[0]}' if len(matches) == 1 else 'REPLAY_MISMATCH'
    return {'status': status, 'actual_curve_test_executed': True,
            'Cstar': old.point_hex(Cstar), 'f_points': f_points,
            'observed_GT': observed.encode().hex(),
            'predicted_GT': [x.encode().hex() for x in predictions],
            'matches': matches, 'native_replay_verified': False,
            'scope': 'Actual independent tiny-curve test; pair contract and source authenticity remain supplied assumptions'}


def fixture_setup(N, tau, beta):
    """Private fixture generator, never called by execute_fact_test()."""
    if tau in range(N + 1) or not 0 < tau < R or not beta % R:
        raise ValueError('Invalid diagnostic setup scalars')
    a, theta, alpha = 7, 19, 9
    h = curve.mul(theta, curve.G)
    pp = {'N': N, 'g': old.point_hex(curve.G), 'h': old.point_hex(h),
          'Y': [old.point_hex(curve.mul(a * pow(tau, k, R), curve.G)) for k in range(N)],
          'W': {str(t): old.point_hex(curve.mul(beta * pow(tau - t, -1, R), curve.G)) for t in range(1, N + 1)},
          'T': [old.point_hex(curve.mul(pow(tau, k, R), h)) for k in range(N)],
          'A': [old.point_hex(curve.mul(a * pow(tau, k, R), h)) for k in range(N - 1)],
          'B': [old.point_hex(curve.mul(beta * pow(tau, k, R), h)) for k in range(N - 1)],
          'Gamma': old.point_hex(curve.mul(alpha + a * pow(tau, N - 1, R), h)),
          'Z': (curve.pairing(curve.G, h) ** alpha).encode().hex()}
    pp['setup_id'] = hashlib.sha256(old.canonical_json(pp)).hexdigest()
    return pp


def fixture_public_view(pp, problem, y, diagnostics):
    """Generate points from private test data; emit only the public input view."""
    tau, beta = diagnostics['tau'], diagnostics['beta']
    w = [diagnostics['ordinary_values'][sid] for sid in problem.source_order]
    r = [diagnostics['pad_values'][sid] for sid in problem.pad_order]
    h = old.point(pp['h'])
    view = {'setup_id': pp['setup_id'], 'ledger_digest': problem.ledger_digest,
            'canonical_records': {}, 'point_handles': {}, 'scalar_answers': {}}
    for a, source in enumerate(problem.sources):
        cp = source['canonical_point']
        if not cp['available']:
            continue
        fact = sum(x * v for x, v in zip(source['fact_map'], y)) % R
        E = curve.linear_combination([(w[a], old.point(pp['g'])),
                                      (-fact, old.point(pp['W'][str(source['node'])]))])
        projections = [old.point_hex(curve.mul(pow(tau, k, R) *
                       ((tau - source['node']) * w[a] - fact * beta), h))
                       for k in range(pp['N'] - 1)]
        view['canonical_records'][cp['handle_id']] = {'source_id': source['source_id'],
                                                     'E': old.point_hex(E), 'projections': projections}
    for row in problem.points:
        if not row['observer_available'] or not row['offset_available']:
            raise ValueError('Generator supports only observer-visible affine observations')
        value = (sum(poly_eval(poly, tau, R) * v for poly, v in zip(row['ordinary'], w))
                 + sum(c * v for c, v in zip(row['pads'], r)) + poly_eval(row['offset'], tau, R)) % R
        view['point_handles'][row['handle_id']] = old.point_hex(curve.mul(value, h))
    for row in problem.scalars:
        actual = (sum(c * v for c, v in zip(row['ordinary'], w))
                  + sum(c * v for c, v in zip(row['pads'], r)) + row['offset']) % R
        if actual != row['rhs']:
            raise ValueError('Synthetic private state disagrees with an actual returned affine RHS')
        view['scalar_answers'][row['observation_id']] = actual
    return view


def compatible_curve_coupling(pp, problem, evidence, diagnostics):
    """Offline validation of the certificate on actual points, not an observer API."""
    delta = evidence['difference']
    shifted = copy.deepcopy(diagnostics)
    for source in problem.sources:
        dy = sum(a * b for a, b in zip(source['fact_map'], delta)) % R
        shift = diagnostics['beta'] * dy * pow(diagnostics['tau'] - source['node'], -1, R)
        sid = source['source_id']
        shifted['ordinary_values'][sid] = (diagnostics['ordinary_values'][sid] + shift) % R
    for sid, shift in zip(problem.pad_order, instantiate_pad_shift(problem, evidence, diagnostics['tau'], diagnostics['beta'])):
        shifted['pad_values'][sid] = (diagnostics['pad_values'][sid] + shift) % R
    view0 = fixture_public_view(pp, problem, evidence['y0'], diagnostics)
    view1 = fixture_public_view(pp, problem, evidence['y1'], shifted)
    if view0 != view1:
        raise AssertionError('Certified compatible coupling changed an actual returned point or scalar')
    return {'status': 'ACTUAL_CURVE_PUBLIC_VIEWS_EQUAL',
            'canonical_records_compared': len(view0['canonical_records']),
            'extra_points_compared': len(view0['point_handles']),
            'scalar_answers_compared': len(view0['scalar_answers']),
            'public_view_sha256': hashlib.sha256(old.canonical_json(view0)).hexdigest(),
            'native_replay_verified': False}, view0


def main():
    histories = json.loads((HERE / 'fact_audit/fixtures.json').read_text())['histories']
    cases, compatible, negative = [], [], []
    output_dir = HERE / 'fact_curve'
    output_dir.mkdir(exist_ok=True)
    actual_inputs = []
    ready_example = None
    for history in histories:
        for stage in history['stages']:
            if stage['query']['kind'] != 'pair' or stage.get('expected', {}).get('compile_error'):
                continue
            raw = copy.deepcopy(stage['ledger'])
            try:
                original = compile_ledger(raw)
            except ValueError:
                continue
            query = stage['query']
            diagnostics = copy.deepcopy(history['fixture_private_diagnostics'])
            evidence0 = audit_pair(original, query['y0'], query['y1'], query['pair_contract'])
            if not evidence0['history_contract_eligible']:
                continue
            taus = [diagnostics['tau']]
            if 'alternate_tau' in stage:
                taus.append(stage['alternate_tau'])
            for tau in taus:
                diagnostics['tau'] = tau
                pp = fixture_setup(original.N, tau, diagnostics['beta'])
                raw['setup_id'] = pp['setup_id']
                problem = compile_ledger(raw)
                evidence = audit_pair(problem, query['y0'], query['y1'], query['pair_contract'])
                name = history['history_id'] + '/' + stage['stage_id'] + '/tau=' + str(tau)
                if evidence['formal_status'] == 'COMPATIBLE':
                    result, view = compatible_curve_coupling(pp, problem, evidence, diagnostics)
                    compatible.append({'case': name, **result})
                    actual_inputs.append({'case': name, 'public_setup': pp, 'ledger': copy.deepcopy(raw),
                                          'evidence': evidence, 'public_view': view, 'coupling_result': result})
                    continue
                for b, y in enumerate((query['y0'], query['y1'])):
                    view = fixture_public_view(pp, problem, y, diagnostics)
                    result = execute_fact_test(pp, raw, evidence, view)
                    if evidence['execution_status'] == 'PAIRING_TEST_RECIPE_READY':
                        collision = stage.get('expected_fixed_tau_collision', False) and tau == taus[0]
                        expected = 'SETUP_COLLISION_INCONCLUSIVE' if collision else 'MATCHES_WORLD_' + str(b)
                        assert result['status'] == expected, (name, b, result)
                        if not collision:
                            ready_example = (pp, raw, evidence, view)
                    else:
                        assert result['status'] == evidence['execution_status']
                    cases.append({'case': name, 'fixture_world_for_external_comparison_only': b, **result})
                    actual_inputs.append({'case': name, 'public_setup': pp, 'ledger': copy.deepcopy(raw),
                                          'evidence': evidence, 'public_view': view, 'execution_result': result})
    assert ready_example is not None
    pp, raw, evidence, view = ready_example
    # A changed observed point cannot be silently accepted as a verified test.
    changed = copy.deepcopy(view)
    handle = evidence['witness']['point_terms'][0]['handle_id']
    changed['point_handles'][handle] = old.point_hex(curve.add(old.point(changed['point_handles'][handle]), old.point(pp['h'])))
    changed_result = execute_fact_test(pp, raw, evidence, changed)
    assert changed_result['status'] == 'REPLAY_MISMATCH'
    negative.append({'case': 'modified_extra_point', 'status': changed_result['status']})
    for name, mutation in (
        ('modified_affine_correction', lambda ev: ev['witness']['known_h_correction_polynomial'].__setitem__(0, (ev['witness']['known_h_correction_polynomial'][0] + 1) % R)),
        ('modified_source_order', lambda ev: ev['source_order'].reverse()),
    ):
        tampered = copy.deepcopy(evidence)
        mutation(tampered)
        if tampered == evidence:  # A singleton order has no nontrivial permutation.
            tampered['source_order'] = ['incorrect-source']
        try:
            execute_fact_test(pp, raw, tampered, view)
        except ValueError as exc:
            negative.append({'case': name, 'status': 'REJECTED', 'reason': str(exc)})
        else:
            raise AssertionError('Tampered evidence was accepted: ' + name)
    summary = {'schema': 'CHARE_FACT_CURVE_RESULTS_V1',
               'backend': 'Actual E/F_523 order-131 reduced Tate pairing from the pinned previous increment',
               'native_replay_verified': False,
               'distinguishing_or_blocked_cases': cases, 'compatible_couplings': compatible,
               'negative_checks': negative,
               'counts': {'actual_curve_tests': sum(x.get('actual_curve_test_executed', False) for x in cases),
                          'distinct_predictions': sum(x['status'].startswith('MATCHES_WORLD_') for x in cases),
                          'setup_collisions': sum(x['status'] == 'SETUP_COLLISION_INCONCLUSIVE' for x in cases),
                          'blocked_pending_tests': sum(x['status'] == 'PENDING_CANONICAL_POINTS' for x in cases),
                          'compatible_couplings': len(compatible), 'negative_checks': len(negative)}}
    saved_path = output_dir / 'public_replay_inputs.json'
    saved_path.write_text(json.dumps(actual_inputs, indent=2) + '\n')
    # Re-read every persisted snapshot. A mutable loop ledger must not rebind
    # an earlier tau=3 fixture when the next fixture uses a different setup.
    serialized_count = 0
    for entry in json.loads(saved_path.read_text()):
        problem = compile_ledger(entry['ledger'])
        verify_evidence(problem, entry['evidence'])
        validate_public_setup(entry['public_setup'], problem)
        if 'execution_result' in entry:
            replayed = execute_fact_test(entry['public_setup'], entry['ledger'],
                                        entry['evidence'], entry['public_view'])
            assert replayed == entry['execution_result'], entry['case']
        else:
            assert entry['public_view']['ledger_digest'] == problem.ledger_digest
            assert hashlib.sha256(old.canonical_json(entry['public_view'])).hexdigest() == entry['coupling_result']['public_view_sha256']
        serialized_count += 1
    summary['counts']['serialized_entries_replayed'] = serialized_count
    (output_dir / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
