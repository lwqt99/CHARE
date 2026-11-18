#!/usr/bin/env python3
"""Independent small-field enumeration and evidence-boundary regressions."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from itertools import combinations, product
from pathlib import Path
import copy
import hashlib
import json
import random
import unittest

import fact_audit as fa
from make_fixtures import PAIR_CONTRACT, ledger, pad, point, scalar, source

HERE = Path(__file__).resolve().parent
COUNTS = {'polynomial_divisions': 0, 'exhaustive_single_mask_systems': 0,
          'random_mixed_systems': 0, 'pad_vectors_enumerated': 0,
          'random_family_systems': 0, 'family_pairs_enumerated': 0}


def independent_poly_add(a, b, p):
    out = [0] * max(len(a), len(b))
    for i in range(len(out)):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return out


def independent_poly_mul(a, b, p):
    out = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            out[i + j] = (out[i + j] + a[i] * b[j]) % p
    return out


def exhaustive_original_numerator_test(raw, difference):
    """Do not call solve/nullspace/divide_linear or use constructed G/U/Q.

    Multiply each original rational displacement by D=prod(X-t_i).  Enumerate
    EVERY pad vector to decide whether each numerator coefficient column is
    in the joint pad image.  This gives an independent finite-field oracle.
    """
    p = raw['p']
    ordinary_ids = [s['source_id'] for s in raw['sources']]
    pad_ids = [s['source_id'] for s in raw['pads']]
    aliases = raw.get('aliases', {})
    def resolve(sid):
        while sid in aliases:
            sid = aliases[sid]
        return sid
    observations = [(False, s) for s in raw['scalars']] + [(True, s) for s in raw['points']]
    numerators, pad_matrix = [], []
    # The numerator degree is at most 2*N-2; use a fixed dense representation.
    width = 2 * len(raw['setup_nodes']) - 1
    for is_point, row in observations:
        coefficients = {sid: [0] for sid in ordinary_ids}
        for sid, value in row.get('ordinary', {}).items():
            val = list(value) if is_point else [value]
            coefficients[resolve(sid)] = independent_poly_add(coefficients[resolve(sid)], val, p)
        numerator = [0] * width
        for supplied in raw['sources']:
            displacement = sum(a * d for a, d in zip(supplied['fact_map'], difference)) % p
            complement = [1]
            for t in raw['setup_nodes']:
                if t != supplied['node']:
                    complement = independent_poly_mul(complement, [-t, 1], p)
            contribution = independent_poly_mul(coefficients[supplied['source_id']], complement, p)
            for k, value in enumerate(contribution):
                numerator[k] = (numerator[k] + displacement * value) % p
        numerators.append(numerator)
        b = [0] * len(pad_ids)
        for sid, value in row.get('pads', {}).items():
            b[pad_ids.index(resolve(sid))] = (b[pad_ids.index(resolve(sid))] + value) % p
        pad_matrix.append(b)
    image = set()
    for v in product(range(p), repeat=len(pad_ids)):
        COUNTS['pad_vectors_enumerated'] += 1
        image.add(tuple(sum(c * x for c, x in zip(row, v)) % p for row in pad_matrix))
    return all(tuple(row[k] for row in numerators) in image for k in range(width))


def random_ledger(rng, facts=2):
    p = 5
    N = rng.choice((2, 3))
    ns, nr = rng.randrange(1, 4), rng.randrange(3)
    ordinary = [source(f'w{a}', rng.randrange(1, N + 1), [rng.randrange(p) for _ in range(facts)]) for a in range(ns)]
    raw = ledger(ordinary, [pad(f'r{j}') for j in range(nr)],
                 [f'fact:{j}' for j in range(facts)], list(range(1, N + 1)))
    raw['p'] = p
    for j in range(rng.randrange(3)):
        offset = rng.randrange(p)
        raw['scalars'].append(scalar(f's{j}', {f'w{a}': rng.randrange(p) for a in range(ns)},
                                     {f'r{a}': rng.randrange(p) for a in range(nr)}, offset, offset))
    for j in range(rng.randrange(1, 4)):
        raw['points'].append(point(f'c{j}', {f'w{a}': [rng.randrange(p) for _ in range(N)] for a in range(ns)},
                                   {f'r{a}': rng.randrange(p) for a in range(nr)},
                                   [rng.randrange(p) for _ in range(N)]))
    return raw


class FactAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        histories = json.loads((HERE / 'fixtures.json').read_text())['histories']
        cls.histories = {h['history_id']: h for h in histories}

    def result(self, history, stage=-1):
        supplied = self.histories[history]['stages'][stage]
        p = fa.compile_ledger(supplied['ledger'])
        q = supplied['query']
        return p, fa.audit_pair(p, q['y0'], q['y1'], q['pair_contract'])

    def test_exact_polynomial_division_exhaustive(self):
        for degree in range(4):
            for coefficients in product(range(5), repeat=degree + 1):
                for node in (1, 2, 3):
                    residue, quotient = fa.divide_linear(coefficients, node, 5)
                    reconstructed = independent_poly_add([residue], independent_poly_mul([-node, 1], quotient, 5), 5)
                    width = max(len(reconstructed), len(coefficients))
                    self.assertEqual((reconstructed + [0] * width)[:width],
                                     (list(coefficients) + [0] * width)[:width])
                    expected_residue = sum(c * pow(node, k, 5) for k, c in enumerate(coefficients)) % 5
                    self.assertEqual(residue, expected_residue)
                    COUNTS['polynomial_divisions'] += 1

    def test_exhaustive_single_mask_original_numerators(self):
        for constant, slope, point_pad, scalar_pad in product(range(5), repeat=4):
            raw = ledger([source('w', 1, [1])], [pad('r')])
            raw['p'] = 5
            raw['points'] = [point('C', {'w': [constant, slope]}, {'r': point_pad}, [2, 1])]
            raw['scalars'] = [scalar('opening', {}, {'r': scalar_pad}, 3, 3)]
            expected = exhaustive_original_numerator_test(raw, [1])
            problem = fa.compile_ledger(raw)
            result = fa.audit_difference(problem, [1])
            self.assertEqual(result['formal_status'] == 'COMPATIBLE', expected)
            self.assertTrue(fa.verify_evidence(problem, result))
            COUNTS['exhaustive_single_mask_systems'] += 1

    def test_random_mixed_systems_against_complete_pad_enumeration(self):
        rng = random.Random(2026111403)
        for _ in range(180):
            raw = random_ledger(rng)
            d = [rng.randrange(5), rng.randrange(5)]
            expected = exhaustive_original_numerator_test(raw, d)
            problem = fa.compile_ledger(raw)
            result = fa.audit_difference(problem, d)
            self.assertEqual(result['formal_status'] == 'COMPATIBLE', expected)
            self.assertTrue(fa.verify_evidence(problem, result))
            COUNTS['random_mixed_systems'] += 1

    def test_family_basis_equals_all_pair_enumeration(self):
        rng = random.Random(9117)
        assignments = list(product((0, 1), repeat=2))
        pairs = [{'pair_id': 'e1', 'y0': [0, 0], 'y1': [1, 0], 'pair_contract': PAIR_CONTRACT},
                 {'pair_id': 'e2', 'y0': [0, 0], 'y1': [0, 1], 'pair_contract': PAIR_CONTRACT}]
        for _ in range(64):
            raw = random_ledger(rng)
            problem = fa.compile_ledger(raw)
            expected = True
            for y0, y1 in combinations(assignments, 2):
                d = [(b - a) % 5 for a, b in zip(y0, y1)]
                brute = exhaustive_original_numerator_test(raw, d)
                direct = fa.audit_pair(problem, y0, y1, PAIR_CONTRACT)
                self.assertEqual(direct['formal_status'] == 'COMPATIBLE', brute)
                expected = expected and brute
                COUNTS['family_pairs_enumerated'] += 1
            span = fa.audit_span(problem, [[1, 0], [0, 1]], 'exact', pairs)
            self.assertEqual(span['formal_status'] == 'COMPATIBLE', expected)
            COUNTS['random_family_systems'] += 1

    def test_compatible_pad_preimages_preserve_all_admissible_tau(self):
        raw = ledger([source('w', 1, [1])], [pad('r')], nodes=[1, 2, 3])
        raw['p'] = 7
        raw['points'] = [point('quadratic', {'w': [2, 3, 4]}, {'r': 2}, [1, 0, 2])]
        problem = fa.compile_ledger(raw)
        result = fa.audit_difference(problem, [1])
        self.assertEqual(result['formal_status'], 'COMPATIBLE')
        for tau in (4, 5, 6):
            for beta in range(1, 7):
                shift = fa.instantiate_pad_shift(problem, result, tau, beta)[0]
                displacement = beta * pow(tau - 1, -1, 7) % 7
                point_change = (sum(c * pow(tau, k, 7) for k, c in enumerate([2, 3, 4])) * displacement + 2 * shift) % 7
                self.assertEqual(point_change, 0)

    def test_pending_prefix_distribution_and_later_recipe(self):
        problem, result = self.result('pending_canonical_point', 0)
        self.assertEqual(result['formal_status'], 'INCOMPATIBLE')
        self.assertEqual(result['execution_status'], 'PENDING_CANONICAL_POINTS')
        self.assertFalse(result['witness']['representation_prerequisites_present'])
        p, tau, beta, t = 7, 3, 2, 1
        before, after = [], []
        for y in (0, 1):
            before.append(Counter((tau - t) * w % p for w in range(p)))
            after.append(Counter(((w - y * beta * pow(tau - t, -1, p)) % p,
                                  (tau - t) * w % p) for w in range(p)))
        self.assertEqual(before[0], before[1])
        self.assertFalse(set(after[0]) & set(after[1]))
        _, later = self.result('pending_canonical_point', 1)
        self.assertEqual(later['execution_status'], 'PAIRING_TEST_RECIPE_READY')
        bad = copy.deepcopy(result)
        bad['execution_status'] = 'PAIRING_TEST_RECIPE_READY'
        with self.assertRaises(fa.FactAuditError):
            fa.verify_evidence(problem, bad)

    def test_affine_rhs_and_polynomial_offsets_in_recipe(self):
        problem, result = self.result('joint_affine_mixed_system')
        w = result['witness']
        self.assertTrue(any(w['c']) and all(w['zeta']))
        self.assertNotEqual(w['known_h_correction_polynomial'], [0])
        self.assertEqual(w['scalar_terms'][0]['actual_rhs'], 103)
        self.assertEqual(w['scalar_terms'][0]['ell'], 94)
        raw = copy.deepcopy(self.histories['joint_affine_mixed_system']['stages'][-1]['ledger'])
        raw['scalars'][0]['rhs'] += 1
        modified = fa.compile_ledger(raw)
        changed = fa.audit_pair(modified, [0], [1], PAIR_CONTRACT)
        self.assertEqual(changed['formal_status'], result['formal_status'])
        self.assertNotEqual(changed['witness']['known_h_correction_polynomial'], w['known_h_correction_polynomial'])
        with self.assertRaises(fa.FactAuditError):
            fa.verify_evidence(modified, result)

    def test_aliases_do_not_create_new_sources_or_change_fact_binding(self):
        old_problem, old = self.result('aliases_keep_original_fact_binding', 0)
        new_problem, new = self.result('aliases_keep_original_fact_binding', 1)
        self.assertEqual(old_problem.source_order, ['w_old', 'w_new'])
        self.assertEqual(old_problem.aliases['copied_retained_w'], 'w_old')
        self.assertEqual(old['formal_status'], 'INCOMPATIBLE')
        self.assertEqual(new['formal_status'], 'COMPATIBLE')
        self.assertEqual(old_problem.A, [[1, 0], [0, 1]])
        raw = copy.deepcopy(self.histories['aliases_keep_original_fact_binding']['stages'][0]['ledger'])
        rebound = copy.deepcopy(raw['sources'][0])
        rebound['fact_map'] = [0, 1]
        raw['sources'].append(rebound)
        with self.assertRaisesRegex(fa.FactAuditError, 'cannot be redefined'):
            fa.compile_ledger(raw)
        raw['sources'].pop()
        raw['aliases']['w_old'] = 'w_new'
        with self.assertRaisesRegex(fa.FactAuditError, 'cannot replace'):
            fa.compile_ledger(raw)

    def test_superset_failure_is_not_actual_pair_failure(self):
        history = self.histories['family_span_and_conservative_superset']
        problem = fa.compile_ledger(history['stages'][0]['ledger'])
        exact_query, super_query = [s['query'] for s in history['stages']]
        exact = fa.audit_span(problem, exact_query['difference_vectors'], 'exact', exact_query['actual_pairs'])
        larger = fa.audit_span(problem, super_query['difference_vectors'], 'superset', super_query['actual_pairs'])
        self.assertEqual(exact['family_status'], 'COMPATIBLE_EXACT_SPAN')
        self.assertEqual(larger['family_status'], 'UNCERTIFIED_SUPERSET')
        self.assertEqual(larger['actual_pair_failure_ids'], [])
        self.assertTrue(all(x['result']['formal_status'] == 'COMPATIBLE' for x in larger['actual_pair_results']))
        self.assertTrue(all(r['execution_status'] in ('DIRECTION_ONLY', 'NO_DISTINGUISHING_WITNESS') for r in larger['basis_results']))
        with self.assertRaisesRegex(fa.FactAuditError, 'exact span'):
            fa.audit_span(problem, super_query['difference_vectors'], 'exact', super_query['actual_pairs'])
        for field, value in (('family_status', 'COMPATIBLE_EXACT_SPAN'),
                             ('actual_pair_failure_ids', ['pair_ab']),
                             ('span_relation', 'exact'),
                             ('execution_status', 'PAIRING_TEST_RECIPE_READY')):
            tampered = copy.deepcopy(larger)
            tampered[field] = value
            with self.assertRaises(fa.FactAuditError):
                fa.verify_evidence(problem, tampered)

    def test_history_extension_rejects_source_rebinding_and_visibility_erasure(self):
        raw = copy.deepcopy(self.histories['bare_pad_then_actual_opening']['stages'][-1]['ledger'])
        before = fa.compile_ledger(raw)
        for change in ('map', 'node', 'generation', 'scalar', 'point', 'rhs'):
            changed = copy.deepcopy(raw)
            if change == 'map':
                changed['sources'][0]['fact_map'] = [0]
            elif change == 'node':
                changed['sources'][0]['node'] = 2
            elif change == 'generation':
                changed['sources'][0]['generation'] = 'new-generation-reusing-old-id'
            elif change == 'scalar':
                changed['scalars'] = []
            elif change == 'point':
                changed['points'] = []
            else:
                changed['scalars'][0]['rhs'] += 1
            with self.assertRaises(fa.FactAuditError):
                fa.verify_history_extension(before, fa.compile_ledger(changed))
        extended = copy.deepcopy(raw)
        extended['sources'].append(source('fresh_new_mask', 2, [1]))
        extended['pads'].append(pad('fresh_pad'))
        self.assertTrue(fa.verify_history_extension(before, fa.compile_ledger(extended))['verified'])
        pending = self.histories['pending_canonical_point']['stages']
        self.assertTrue(fa.verify_history_extension(fa.compile_ledger(pending[0]['ledger']),
                                                  fa.compile_ledger(pending[1]['ledger']))['verified'])

    def test_nonzero_rational_can_collide_at_fixed_tau(self):
        problem, result = self.result('formal_nonzero_fixed_tau_collision')
        self.assertTrue(result['witness']['rational_difference']['formal_nonzero'])
        self.assertTrue(fa.evaluate_rational_witness(problem, result, 3, 7)['fixed_tau_collision'])
        self.assertFalse(fa.evaluate_rational_witness(problem, result, 4, 7)['fixed_tau_collision'])
        self.assertFalse(result['native_replay_verified'])

    def test_private_offsets_and_unavailable_answers_block_public_recipe(self):
        problem, result = self.result('private_offset_is_formal_only')
        self.assertFalse(result['history_contract_eligible'])
        self.assertEqual(result['model_scope'], 'FORMAL_PRIVATE_DESCRIPTOR_ONLY')
        self.assertIsNone(result['witness']['known_h_correction_polynomial'])
        self.assertEqual(result['execution_status'], 'REPRESENTATION_PREREQUISITES_MISSING')
        raw = copy.deepcopy(self.histories['private_offset_is_formal_only']['stages'][0]['ledger'])
        raw['points'][0]['offset'] = [730001]
        with self.assertRaisesRegex(fa.FactAuditError, 'instrumented secret'):
            fa.compile_ledger(raw)
        raw = copy.deepcopy(self.histories['bare_pad_then_actual_opening']['stages'][-1]['ledger'])
        raw['scalars'][0]['rhs_available'], raw['scalars'][0]['rhs'] = False, None
        p = fa.compile_ledger(raw)
        r = fa.audit_pair(p, [0], [1], PAIR_CONTRACT)
        self.assertEqual(r['formal_status'], 'INCOMPATIBLE')
        self.assertFalse(r['history_contract_eligible'])
        self.assertEqual(r['execution_status'], 'REPRESENTATION_PREREQUISITES_MISSING')

    def test_world_dependent_offsets_are_outside_release_grammar(self):
        raw = self.histories['world_dependent_offset_rejected']['stages'][0]['ledger']
        with self.assertRaisesRegex(fa.FactAuditError, 'UNSUPPORTED_MODEL'):
            fa.compile_ledger(raw)
        # Canonical F0 is invariant under BOTH source and y-dependent offset
        # shifts. Treating it as an extra fixed-offset release would be wrong.
        p, tau, beta, t, w = 7, 3, 2, 1, 4
        shifted_w = (w + beta * pow(tau - t, -1, p)) % p
        self.assertEqual((tau - t) * w % p, ((tau - t) * shifted_w - beta) % p)

    def test_factual_openings_and_pair_contract_are_separate_prerequisites(self):
        raw = ledger([source('v', 1, [0], 'core')])
        raw['factual_openings'] = [{'opening_id': 'y_opened', 'coefficients': [1], 'rhs': 1,
                                    'provenance': 'Actual disclosed qualification'}]
        problem = fa.compile_ledger(raw)
        r = fa.audit_pair(problem, [0], [1], PAIR_CONTRACT)
        self.assertEqual(r['formal_status'], 'COMPATIBLE')
        self.assertFalse(r['actual_factual_openings_match_both'])
        self.assertEqual(r['pair_status'], 'PAIR_CONTRACT_FAILED')
        problem, _ = self.result('formal_nonzero_fixed_tau_collision')
        r = fa.audit_pair(problem, [0], [1])
        self.assertEqual(r['execution_status'], 'PAIR_CONTRACT_UNVERIFIED')
        self.assertFalse(r['pair_legality_verified'])

    def test_verifier_rejects_tampered_preimages_witnesses_and_native_claims(self):
        problem, r = self.result('bare_pad_then_actual_opening', 0)
        bad = copy.deepcopy(r)
        bad['certificate']['pole_preimages'][0]['vector'][0] += 1
        with self.assertRaises(fa.FactAuditError):
            fa.verify_evidence(problem, bad)
        problem, r = self.result('joint_affine_mixed_system')
        for change in ('c', 'f', 'correction', 'native'):
            bad = copy.deepcopy(r)
            if change == 'c':
                bad['witness']['c'][0] += 1
            elif change == 'f':
                bad['witness']['f_polynomials'][0][0] += 1
            elif change == 'correction':
                bad['witness']['known_h_correction_polynomial'][0] += 1
            else:
                bad['native_replay_verified'] = True
            with self.assertRaises(fa.FactAuditError):
                fa.verify_evidence(problem, bad)

    def test_boundaries_zero_pads_zero_rows_N_one_and_empty_affine_fiber(self):
        raw = ledger([source('w', 1, [1])], nodes=[1])
        raw['p'] = 3
        problem = fa.compile_ledger(raw)
        r = fa.audit_difference(problem, [1])
        self.assertEqual(r['formal_status'], 'COMPATIBLE')
        self.assertEqual(r['certificate']['polynomial_preimages'], [])
        raw['points'] = [point('plain', {'w': [1]})]
        self.assertEqual(fa.audit_difference(fa.compile_ledger(raw), [1])['formal_status'], 'INCOMPATIBLE')
        raw['scalars'] = [scalar('impossible', {}, {}, 1)]
        with self.assertRaisesRegex(fa.FactAuditError, 'empty fiber'):
            fa.compile_ledger(raw)
        for field in (4, 9, 341):
            invalid = ledger([source('w', 1, [1])])
            invalid['p'] = field
            with self.assertRaisesRegex(fa.FactAuditError, 'prime field'):
                fa.compile_ledger(invalid)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FactAuditTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {'schema': 'CHARE_FACT_TEST_SUMMARY_V1', 'generated_at_utc': datetime.now(timezone.utc).isoformat(),
              'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'all_passed': result.wasSuccessful(), 'independent_enumeration_counts': COUNTS,
              'scope': 'Original cleared-denominator polynomials and exhaustive pad images; no generic-group/native replay',
              'solver_sha256': hashlib.sha256((HERE / 'fact_audit.py').read_bytes()).hexdigest()}
    (HERE / 'results').mkdir(exist_ok=True)
    (HERE / 'results' / 'test_summary.json').write_text(json.dumps(report, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
