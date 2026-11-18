#!/usr/bin/env python3
"""Build deterministic new qualification-compatibility fixtures."""
from pathlib import Path
import copy
import json

HERE = Path(__file__).resolve().parent
PAIR_CONTRACT = {'legal_pair': True, 'same_public_metadata_and_outcomes': True,
                 'fixed_before_fresh_sources': True,
                 'provenance': 'Synthetic fixed pair chosen before independent fixture source draws'}


def source(sid, node, fact_map, kind='mask', available=True, generation=None):
    return {'source_id': sid, 'kind': kind, 'slot': f'slot:{node}', 'node': node,
            'generation': generation or f'generation:{sid}', 'fact_map': fact_map,
            'canonical_point': {'handle_id': f'E:{sid}', 'available': available,
                                'provenance': f'Canonical generator for immutable {sid}' if available else ''}}


def pad(sid):
    return {'source_id': sid, 'generation': f'pad-generation:{sid}'}


def point(oid, ordinary, pads=None, offset=None, **extra):
    return {'observation_id': oid, 'ordinary': ordinary, 'pads': pads or {},
            'offset': offset if offset is not None else [0], 'offset_available': True,
            'handle_id': f'handle:{oid}', 'observer_available': True,
            'world_invariant': True,
            'provenance': 'Fixed coefficients and offset on the same public prefix', **extra}


def scalar(oid, ordinary, pads, rhs, offset=0, **extra):
    return {'observation_id': oid, 'ordinary': ordinary, 'pads': pads, 'offset': offset,
            'offset_available': True, 'rhs': rhs, 'rhs_available': True,
            'observer_available': True, 'world_invariant': True,
            'provenance': 'Actual returned affine answer under fixed common-prefix coefficients', **extra}


def ledger(sources, pads=None, facts=None, nodes=None):
    return {'schema': 'CHARE_FACT_LEDGER_V1', 'p': 131,
            'setup_id': 'synthetic-fact-reference-setup', 'setup_nodes': nodes or [1, 2],
            'fact_ids': facts or ['qualification:q0'], 'sources': sources, 'pads': pads or [],
            'aliases': {}, 'scalars': [], 'points': [], 'factual_openings': [],
            'public_powers_available': True}


def pair(y0=None, y1=None):
    return {'kind': 'pair', 'y0': y0 or [0], 'y1': y1 or [1], 'pair_contract': PAIR_CONTRACT}


def stage(name, raw, formal, execution, query=None, **extra):
    return {'stage_id': name, 'ledger': copy.deepcopy(raw), 'query': query or pair(),
            'expected': {'formal_status': formal, 'execution_status': execution}, **extra}


def private(values, pads=None, tau=4):
    return {'observer_visible': False, 'scope': 'Synthetic exponent-model diagnostics only',
            'tau': tau, 'beta': 7, 'ordinary_values': values, 'pad_values': pads or {}}


def build():
    histories = []
    raw = ledger([source('v1', 1, [0], 'core'), source('w1', 1, [1])], [pad('r1')])
    raw['points'] = [point('masked_quotient', {'w1': [-1, 1]}, {'r1': 1})]
    stages = [stage('bare_pad_hides_quotient', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS')]
    raw['points'].append(point('negative_pad', {}, {'r1': -1}))
    stages.append(stage('joint_pad_cancellation', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY',
                        require_zero_residues=True, require_nonzero_quotient=True))
    histories.append({'history_id': 'residue_zero_quotient_leak_key_protected',
                      'description': 'The restored quotient distinguishes qualifications while all ordinary residues are zero.',
                      'key_integration_expectation': {'target_source': 'v1', 'status': 'PROTECTED',
                                                     'verification_owner': 'round3 joint integration, not this runner'},
                      'stages': stages, 'fixture_private_diagnostics': private({'v1': 17, 'w1': 29}, {'r1': 43})})

    raw = ledger([source('v1', 1, [0], 'core'), source('w1', 1, [1])])
    stages = [stage('before_release', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS')]
    raw['points'].append(point('core_release', {'v1': [1]}))
    stages.append(stage('core_released', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS'))
    histories.append({'history_id': 'core_release_facts_compatible',
                      'description': 'A core has a zero fact-map row, even when its release admits key recovery.',
                      'key_integration_expectation': {'target_source': 'v1', 'status': 'FORMAL_WITNESS',
                                                     'verification_owner': 'round3 joint integration, not this runner'},
                      'stages': stages, 'fixture_private_diagnostics': private({'v1': 17, 'w1': 29})})

    raw = ledger([source('w1', 1, [1])], [pad('r1')])
    raw['points'] = [point('masked_constant', {'w1': [1]}, {'r1': 1}, [6, 2])]
    stages = [stage('pad_not_opened', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS')]
    raw['scalars'].append(scalar('pad_opened_with_offset', {}, {'r1': 1}, 48, 5))
    stages.append(stage('retained_point_after_opening', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY'))
    histories.append({'history_id': 'bare_pad_then_actual_opening',
                      'description': 'The same retained point becomes incompatible after its original pad is opened.',
                      'stages': stages, 'fixture_private_diagnostics': private({'w1': 29}, {'r1': 43})})

    raw = ledger([source('wA', 1, [1]), source('wB', 1, [1])])
    raw['points'] = [point('same_fact_mask_difference', {'wA': [1], 'wB': [-1]}, offset=[8, 2])]
    histories.append({'history_id': 'same_fact_mask_difference',
                      'description': 'Two fresh masks with the same fact displacement cancel under the prescribed shift.',
                      'stages': [stage('difference_released', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS')],
                      'fixture_private_diagnostics': private({'wA': 29, 'wB': 47})})

    raw = ledger([source('w_pending', 1, [1], available=False)])
    raw['points'] = [point('pending_polynomial', {'w_pending': [-1, 1]})]
    stages = [stage('before_canonical_point', raw, 'INCOMPATIBLE', 'PENDING_CANONICAL_POINTS')]
    raw['sources'][0]['canonical_point'].update(available=True, provenance='Canonical point published for the original generation')
    stages.append(stage('after_canonical_point', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY'))
    histories.append({'history_id': 'pending_canonical_point',
                      'description': 'A formal incompatibility before E is published is not an executed distinguishing attack.',
                      'stages': stages, 'fixture_private_diagnostics': private({'w_pending': 29})})

    raw = ledger([source('w_old', 1, [1, 0]), source('w_new', 1, [0, 1])],
                 [pad('r_old')], ['qualification:old', 'qualification:new'])
    raw['aliases'] = {'retained_w': 'w_old', 'copied_retained_w': 'retained_w', 'retained_pad': 'r_old'}
    raw['points'] = [point('old_delivery', {'copied_retained_w': [-1, 1]}, {'r_old': 1})]
    raw['scalars'] = [scalar('old_pad_opening', {}, {'retained_pad': 1}, 43)]
    histories.append({'history_id': 'aliases_keep_original_fact_binding',
                      'description': 'A copied old generation still binds the old fact row after a fresh new generation exists.',
                      'stages': [stage('old_fact_pair', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY', pair([0, 0], [1, 0])),
                                 stage('new_fact_pair', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS', pair([0, 0], [0, 1]))],
                      'fixture_private_diagnostics': private({'w_old': 29, 'w_new': 47}, {'r_old': 43})})

    raw = ledger([source('w1', 1, [1]), source('w2', 2, [1])],
                 [pad('rA'), pad('rB')], nodes=[1, 2, 3])
    raw['points'] = [point('mixed_C1', {'w1': [-1, 1], 'w2': [2]}, {'rA': 1, 'rB': 2}, [7, 3, 5]),
                     point('mixed_C2', {'w1': [1], 'w2': [-2, 1]}, {'rA': 3, 'rB': -1}, [11, 4])]
    stages = [stage('points_without_relation', raw, 'COMPATIBLE', 'NO_DISTINGUISHING_WITNESS')]
    raw['scalars'] = [scalar('mixed_affine_answer', {'w1': 1}, {'rA': 2, 'rB': 1}, 103, 9)]
    stages.append(stage('joint_scalar_and_points', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY', require_mixed_witness=True))
    histories.append({'history_id': 'joint_affine_mixed_system',
                      'description': 'Joint T=(Lr;B), nonzero ordinary scalar coefficients, actual RHS, and polynomial offsets all matter.',
                      'stages': stages, 'fixture_private_diagnostics': private({'w1': 17, 'w2': 29}, {'rA': 23, 'rB': 31}, tau=5)})

    raw = ledger([source('w1', 1, [1, -1, 0])], facts=['fact:a', 'fact:b', 'fact:c'])
    raw['points'] = [point('fact_difference_probe', {'w1': [-1, 1]})]
    actual_pairs = [{'pair_id': 'pair_ab', **pair([0, 0, 0], [1, 1, 0])},
                    {'pair_id': 'pair_c', **pair([0, 0, 0], [0, 0, 1])}]
    exact = {'kind': 'span', 'difference_vectors': [[1, 1, 0], [0, 0, 1]],
             'span_relation': 'exact', 'actual_pairs': actual_pairs,
             'family_assignments': [[0, 0, 0], [1, 1, 0], [0, 0, 1], [1, 1, 1]]}
    superset = {**exact, 'difference_vectors': [[1, 1, 0], [0, 0, 1], [1, 0, 0]], 'span_relation': 'superset'}
    histories.append({'history_id': 'family_span_and_conservative_superset',
                      'description': 'An exact legal-family span passes; a larger span can fail without an incompatible actual pair.',
                      'stages': [stage('exact_family', raw, 'COMPATIBLE', 'SEE_EXPLICIT_PAIR_RESULTS_ONLY', exact,
                                       expected_family_status='COMPATIBLE_EXACT_SPAN'),
                                 stage('larger_conservative_span', raw, 'INCOMPATIBLE_DIRECTION', 'SEE_EXPLICIT_PAIR_RESULTS_ONLY', superset,
                                       expected_family_status='UNCERTIFIED_SUPERSET')],
                      'fixture_private_diagnostics': private({'w1': 29})})

    raw = ledger([source('w1', 1, [1])])
    raw['points'] = [point('vanishes_at_three', {'w1': [-3, 1]})]
    histories.append({'history_id': 'formal_nonzero_fixed_tau_collision',
                      'description': 'A nonzero formal rational witness can evaluate to zero at the legal tau=3.',
                      'stages': [stage('collision_at_tau_three', raw, 'INCOMPATIBLE', 'PAIRING_TEST_RECIPE_READY',
                                       expected_fixed_tau_collision=True, alternate_tau=4)],
                      'fixture_private_diagnostics': private({'w1': 29}, tau=3)})

    raw = ledger([source('w1', 1, [1])])
    raw['points'] = [point('opaque_fixed_offset', {'w1': [-1, 1]}, offset_available=False)]
    raw['points'][0]['offset'] = None
    histories.append({'history_id': 'private_offset_is_formal_only',
                      'description': 'An unknown but stipulated world-invariant affine offset blocks the public correction recipe.',
                      'stages': [stage('private_descriptor', raw, 'INCOMPATIBLE', 'REPRESENTATION_PREREQUISITES_MISSING',
                                       expected_history_contract_eligible=False)],
                      'fixture_private_diagnostics': private({'w1': 29})})

    raw = ledger([source('w1', 1, [1])])
    raw['points'] = [point('canonical_projection_not_extra_release', {'w1': [-1, 1]}, world_invariant=False)]
    histories.append({'history_id': 'world_dependent_offset_rejected',
                      'description': 'The canonical F0=(tau-t)w-y*beta is not an extra world-invariant-offset release.',
                      'stages': [{'stage_id': 'outside_declared_release_grammar', 'ledger': raw, 'query': pair(),
                                  'expected_error': 'UNSUPPORTED_MODEL'}],
                      'fixture_private_diagnostics': private({'w1': 29})})
    return {'schema': 'CHARE_FACT_FIXTURES_V1', 'scope': 'Independent finite-field source-coefficient diagnostics',
            'native_replay_verified': False, 'histories': histories}


if __name__ == '__main__':
    output = HERE / 'fixtures.json'
    output.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + '\n')
    print(f'Wrote {len(build()["histories"])} deterministic histories to {output.name}')
