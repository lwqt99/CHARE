#!/usr/bin/env python3
"""Coefficient-only reference joining key and fixed-pair fact admission.

Prospective inputs are public point-release descriptors, not private scalar
answers or cryptographic payloads.  Existing scalar answers are already public.
This is not the original delivery engine, a transaction database, or a native
cryptographic validity checker.  The target and legal-pair contracts are inputs.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path

from prior_runtime import load_auditor
from fact_audit.fact_audit import compile_ledger, audit_pair, verify_evidence, poly_eval, digest

old = load_auditor()
HERE = Path(__file__).resolve().parent


def formal_key_assessment(problem, target):
    """Residue adapter for formal capability only; export no point recipes.

    The polynomial projection kernel is completed for the formal test.  Setting
    the internal representative's affine constant to zero does not assert that
    the observed point has zero constant or that its residue is represented.
    """
    registry = old.Registry(problem.p)
    for source in problem.sources:
        registry.add(old.Source(source_id=source['source_id'], kind=source['kind'],
                                owner='declared-source-generator', slot=source['node'],
                                generation=source['generation']))
    for source in problem.pads:
        registry.add(old.Source(source_id=source['source_id'], kind='pad',
                                owner='declared-pad-generator', slot=None,
                                generation=source['generation']))
    for alias, source in problem.aliases.items():
        registry.alias(alias, source)
    observations = []
    for row in problem.scalars:
        if not (row['observer_available'] and row['offset_available'] and row['rhs_available']):
            raise ValueError('A public key audit cannot use private scalar descriptors or answers')
        observations.append(old.Observation(row['observation_id'], 'scalar',
             dict(zip(problem.source_order, row['ordinary'])), dict(zip(problem.pad_order, row['pads'])),
             constant=row['offset'], rhs=row['rhs'], rhs_provenance=row['provenance'],
             origin='already_public_affine_answer'))
    for row in problem.points:
        if not (row['observer_available'] and row['offset_available']):
            raise ValueError('A public joint audit cannot use private point descriptors or offsets')
        residues = [poly_eval(poly, source['node'], problem.p)
                    for poly, source in zip(row['ordinary'], problem.sources)]
        observations.append(old.Observation(row['observation_id'], 'point',
              dict(zip(problem.source_order, residues)), dict(zip(problem.pad_order, row['pads'])),
              constant=0, origin='FORMAL_RESIDUE_REPRESENTATIVE_ONLY'))
    if target.get('validated_original_target_contract') is not True:
        raise ValueError('The reference requires a validated original-target input contract')
    if len(target['columns']) != len(target['nodes']) or not target['columns']:
        raise ValueError('Malformed original target')
    for column, node in zip(target['columns'], target['nodes']):
        if node not in problem.setup_nodes:
            raise ValueError('Target node is outside the original setup')
        for sid, coefficient in registry.coefficients(column, 'ordinary').items():
            if coefficient and registry.sources[sid].slot != node:
                raise ValueError('The declared target column has an inconsistent source slot')
    target_input = old.Target(target_id=target['target_id'], columns=tuple(target['columns']),
          nodes=tuple(target['nodes']), recorded_eta=None, context_id=target['original_context_id'],
          certified_nonzero_slots=tuple(target.get('certified_nonzero_slots', [])),
          certification_provenance=target.get('certification_provenance', ''))
    capability = old.capability(registry, observations)
    key_problem = old.problem_for(target_input, registry, 'public_D')
    result = old.audit(key_problem, capability['basis'], problem.p)
    old.verify_audit(key_problem, capability['basis'], result, problem.p)
    return {'result': result, 'formal_capability_basis': capability['basis'],
            'formal_capability_rank': capability['rank'], 'source_order': problem.source_order,
            'residual_mode': 'public_D', 'private_eta_read': False,
            'certified_nonzero_slots': list(target.get('certified_nonzero_slots', [])),
            'scope': 'Completed formal residue space only; no actual point recipe or recovery is asserted'}


def assess_ledger(raw, targets, fact_query):
    problem = compile_ledger(raw)
    if fact_query.get('kind') != 'fixed_pair':
        raise ValueError('This joint wrapper accepts an explicitly supplied fixed pair only')
    fact = audit_pair(problem, fact_query['y0'], fact_query['y1'], fact_query.get('pair_contract'))
    verify_evidence(problem, fact)
    keys = [formal_key_assessment(problem, target) for target in targets]
    keys_ok = all(x['result']['status'] == 'PROTECTED' for x in keys)
    facts_ok = (fact['formal_status'] == 'COMPATIBLE' and fact['history_contract_eligible']
                and fact['pair_status'] == 'CONDITIONAL_LEGAL_PAIR')
    return {'keys_certified': keys_ok, 'facts_compatible_for_declared_pair': facts_ok,
            'joint_certified': keys_ok and facts_ok, 'keys': keys,
            'fact_evidence': fact, 'ledger_digest': problem.ledger_digest,
            'native_replay_verified': False,
            'scope': 'Formal coefficient admission for declared original targets and one supplied legal-pair contract'}


class JointGuard:
    def __init__(self, ledger, targets, fact_query):
        self._ledger = copy.deepcopy(ledger)
        self._targets = copy.deepcopy(targets)
        self._query = copy.deepcopy(fact_query)
        self._plans = {}
        self._unmodeled_events = 0
        self._immutable = digest({k: self._ledger.get(k) for k in
                                 ('p', 'setup_id', 'setup_nodes', 'fact_ids', 'sources', 'pads', 'aliases')})
        self.events = []
        self._current = assess_ledger(self._ledger, self._targets, self._query)

    def snapshot(self):
        return copy.deepcopy({'visible_ledger': self._ledger, 'frozen_plans': self._plans,
                              'events': self.events, 'unmodeled_visible_events': self._unmodeled_events,
                              'current': self._current})

    def _extended(self, points=()):
        if self._unmodeled_events:
            raise ValueError('The visible history contains an unsupported observation field set')
        proposed = copy.deepcopy(self._ledger)
        proposed['points'].extend(copy.deepcopy(list(points)))
        present = {row['observation_id']: row for row in proposed['points']}
        for plan in self._plans.values():
            for row in plan:
                oid = row['observation_id']
                if oid in present:
                    if digest(present[oid]) != digest(row):
                        raise ValueError('An observed or proposed point changed a frozen plan descriptor')
                else:
                    proposed['points'].append(copy.deepcopy(row))
                    present[oid] = row
        return proposed

    def preflight_points(self, points):
        # The input contains only known coefficients, offsets, identities and a
        # future handle name.  No point encoding, secret RHS or scalar value.
        points = copy.deepcopy(list(points))
        allowed = {'observation_id', 'ordinary', 'pads', 'offset', 'offset_available',
                   'handle_id', 'observer_available', 'world_invariant', 'provenance'}
        if any(set(row) - allowed for row in points):
            raise ValueError('Prospective point descriptors cannot contain scalar answers or payloads')
        before = digest(self.snapshot())
        assessment = assess_ledger(self._extended(points), self._targets, self._query)
        decision = 'ADMIT_COEFFICIENT_PLAN' if assessment['joint_certified'] else 'REJECT_COEFFICIENT_PLAN'
        assert digest(self.snapshot()) == before
        return {'decision': decision, 'assessment': assessment,
                'visible_state_unchanged': True, 'candidate_digest': digest(points),
                'candidate_payload_generated': False}

    def freeze_point_plan(self, plan_id, points):
        if not isinstance(plan_id, str) or not plan_id or plan_id in self._plans:
            raise ValueError('Frozen plan ID must be new and nonempty')
        proposal = copy.deepcopy(list(points))
        result = self.preflight_points(proposal)
        if result['decision'] == 'ADMIT_COEFFICIENT_PLAN':
            self._plans[plan_id] = proposal
            self._current = assess_ledger(self._extended(), self._targets, self._query)
        return result

    def observe(self, kind, row):
        """Append an already public answer first; a failed audit never erases it."""
        if kind not in ('point', 'scalar'):
            raise ValueError('Only already visible point/scalar descriptors are modeled')
        key = 'points' if kind == 'point' else 'scalars'
        common = {'observation_id', 'ordinary', 'pads', 'offset', 'offset_available',
                  'observer_available', 'world_invariant', 'provenance'}
        allowed = common | ({'handle_id'} if kind == 'point' else {'rhs', 'rhs_available'})
        # An already visible point is public; a private descriptor attached by
        # an instrumented caller is not.  Never persist it in a public snapshot
        # or a public hash, even on the error path.
        retained = {k: copy.deepcopy(v) for k, v in row.items() if k in allowed}
        if retained.get('offset_available', True) is not True:
            retained['offset'] = None
        if kind == 'scalar' and retained.get('rhs_available', True) is not True:
            retained['rhs'] = None
        if retained.get('observer_available', True) is not True:
            retained = {'observation_id': 'unavailable-observation-' + str(len(self.events)),
                        'ordinary': {}, 'pads': {}, 'offset': None, 'offset_available': False,
                        'observer_available': False, 'world_invariant': False,
                        'provenance': 'Unresolved input marked unavailable to the observer'}
            if kind == 'scalar':
                retained.update(rhs=None, rhs_available=False)
            self._unmodeled_events += 1
        if set(row) - allowed:
            self._unmodeled_events += 1
        self._ledger[key].append(retained)
        self.events.append({'kind': kind, 'observation_id': retained.get('observation_id'),
                            'visibility': 'ALREADY_PUBLIC_BEFORE_AUDIT'})
        try:
            self._current = assess_ledger(self._extended(), self._targets, self._query)
            decision = 'VISIBLE_HISTORY_CERTIFIED' if self._current['joint_certified'] else 'VISIBLE_HISTORY_CONTRACT_FAILURE'
        except ValueError as exc:
            self._current = {'joint_certified': False, 'error': str(exc)}
            decision = 'VISIBLE_SOURCE_LANGUAGE_FAILURE'
        return {'decision': decision, 'observation_retained': True,
                'assessment': copy.deepcopy(self._current)}

    def check_same_source_bindings(self, proposed_ledger):
        candidate = digest({k: proposed_ledger.get(k) for k in
                            ('p', 'setup_id', 'setup_nodes', 'fact_ids', 'sources', 'pads', 'aliases')})
        if candidate != self._immutable:
            raise ValueError('This reference forbids rebinding old source identities, fact maps, generations, nodes or aliases')
        return True


def demonstration_inputs():
    contract = {'legal_pair': True, 'same_public_metadata_and_outcomes': True,
                'fixed_before_fresh_sources': True, 'provenance': 'Synthetic one-bit qualification family {0,1}'}
    def source(sid, kind, fact):
        return {'source_id': sid, 'kind': kind, 'slot': 'slot:1', 'node': 1,
                'generation': 'generation:' + sid, 'fact_map': [fact],
                'canonical_point': {'handle_id': 'E:' + sid, 'available': True,
                                    'provenance': 'Synthetic original canonical source'}}
    ledger = {'p': 131, 'setup_id': 'synthetic-joint-reference', 'setup_nodes': [1, 2],
              'fact_ids': ['qualification:q0'], 'sources': [source('v', 'core', 0), source('w', 'mask', 1)],
              'pads': [{'source_id': 'r', 'generation': 'pad-generation:r'}], 'aliases': {'retained:w': 'w'},
              'scalars': [], 'points': [], 'factual_openings': [], 'public_powers_available': True}
    target = {'target_id': 'original-singleton-core-target', 'columns': [{'v': 1}], 'nodes': [1],
              'original_context_id': 'original-context-not-retargeted',
              'validated_original_target_contract': True, 'certified_nonzero_slots': []}
    query = {'kind': 'fixed_pair', 'y0': [0], 'y1': [1], 'pair_contract': contract}
    def point(name, ordinary, pads=None):
        return {'observation_id': name, 'ordinary': ordinary, 'pads': pads or {},
                'offset': [3, 2], 'offset_available': True, 'handle_id': 'handle:' + name,
                'observer_available': True, 'world_invariant': True,
                'provenance': 'Public coefficients fixed before the candidate point is generated'}
    points = {'masked': point('masked-w', {'retained:w': [1]}, {'r': 1}),
              'quotient': point('quotient-w', {'w': [-1, 1]}),
              'core': point('core-v', {'v': [1]}),
              'pad_open': point('pad-r', {}, {'r': 1})}
    return ledger, [target], query, points


def main():
    ledger, targets, query, points = demonstration_inputs()
    matrix = []
    for name, candidates, expected in (
        ('both_certified', [points['masked']], (True, True)),
        ('key_only_certified', [points['quotient']], (True, False)),
        ('facts_only_compatible', [points['core']], (False, True)),
        ('neither_certified', [points['core'], points['quotient']], (False, False)),
    ):
        guard = JointGuard(ledger, targets, query)
        result = guard.preflight_points(candidates)
        outcome = result['assessment']
        assert (outcome['keys_certified'], outcome['facts_compatible_for_declared_pair']) == expected
        assert result['visible_state_unchanged'] and not result['candidate_payload_generated']
        matrix.append({'case': name, 'point_candidates': candidates, **result})
    diagnostics = []
    guard = JointGuard(ledger, targets, query)
    frozen = guard.freeze_point_plan('future-pad-release', [points['pad_open']])
    assert frozen['decision'] == 'ADMIT_COEFFICIENT_PLAN'
    before = digest(guard.snapshot())
    denied = guard.preflight_points([points['masked']])
    assert denied['decision'] == 'REJECT_COEFFICIENT_PLAN' and digest(guard.snapshot()) == before
    diagnostics.append({'case': 'frozen_future_pad_opening', 'frozen': frozen['decision'],
                        'later_candidate': denied['decision'], 'no_visible_state_mutation': True})
    seen = guard.observe('point', points['masked'])
    assert seen['decision'] == 'VISIBLE_HISTORY_CONTRACT_FAILURE'
    diagnostics.append({'case': 'visible_payload_checked_with_frozen_future', **seen})
    guard = JointGuard(ledger, targets, query)
    guard.freeze_point_plan('unchanged-pad-plan', [points['pad_open']])
    seen = guard.observe('point', points['pad_open'])
    assert seen['decision'] == 'VISIBLE_HISTORY_CERTIFIED'
    assert seen['assessment']['fact_evidence']['point_order'] == [points['pad_open']['observation_id']]
    diagnostics.append({'case': 'fulfilled_frozen_plan_counted_once', **seen})
    # Observations are retained even when the application notices the violation late.
    guard = JointGuard(ledger, targets, query)
    seen = guard.observe('point', points['quotient'])
    assert seen['decision'] == 'VISIBLE_HISTORY_CONTRACT_FAILURE'
    assert guard.snapshot()['visible_ledger']['points'] == [points['quotient']]
    diagnostics.append({'case': 'already_visible_quotient_retained', **seen})
    guard = JointGuard(ledger, targets, query)
    assert guard.observe('point', points['masked'])['decision'] == 'VISIBLE_HISTORY_CERTIFIED'
    scalar = {'observation_id': 'already-public-pad-answer', 'ordinary': {}, 'pads': {'r': 1},
              'rhs': 48, 'offset': 5, 'offset_available': True, 'rhs_available': True,
              'observer_available': True, 'world_invariant': True,
              'provenance': 'Actual affine answer already returned to the observer'}
    seen = guard.observe('scalar', scalar)
    assert seen['decision'] == 'VISIBLE_HISTORY_CONTRACT_FAILURE'
    assert guard.snapshot()['visible_ledger']['scalars'] == [scalar]
    diagnostics.append({'case': 'actual_scalar_opening_rechecks_retained_point', **seen})
    for field in ('fact_map', 'generation', 'node'):
        changed = copy.deepcopy(ledger)
        changed['sources'][1][field] = {'fact_map': [0], 'generation': 'new-generation', 'node': 2}[field]
        try:
            guard.check_same_source_bindings(changed)
        except ValueError as exc:
            diagnostics.append({'case': 'rebind_old_' + field, 'status': 'REJECTED', 'reason': str(exc)})
        else:
            raise AssertionError('Source rebinding was accepted')
    candidate = copy.deepcopy(points['masked']); candidate['private_rhs'] = 73
    try:
        guard.preflight_points([candidate])
    except ValueError as exc:
        diagnostics.append({'case': 'private_candidate_rhs_forbidden', 'status': 'REJECTED', 'reason': str(exc)})
    else:
        raise AssertionError('A prospective private RHS crossed the public interface')
    # Published source-language failures remain in the log as well.
    guard = JointGuard(ledger, targets, query)
    malformed = copy.deepcopy(points['masked']); malformed['world_invariant'] = False
    seen = guard.observe('point', malformed)
    assert seen['decision'] == 'VISIBLE_SOURCE_LANGUAGE_FAILURE'
    assert len(guard.snapshot()['visible_ledger']['points']) == 1
    diagnostics.append({'case': 'already_visible_outside_model_retained', **seen})
    for private_kind, field, availability, value in (
        ('point', 'offset', 'offset_available', [730001]),
        ('scalar', 'rhs', 'rhs_available', 41009),
    ):
        guard = JointGuard(ledger, targets, query)
        row = copy.deepcopy(points['masked'] if private_kind == 'point' else scalar)
        row[field], row[availability] = value, False
        seen = guard.observe(private_kind, row)
        snapshot = guard.snapshot()
        stored = snapshot['visible_ledger']['points' if private_kind == 'point' else 'scalars'][0]
        assert stored[field] is None and not seen['assessment']['joint_certified']
        assert ('730001' if private_kind == 'point' else '41009') not in json.dumps(snapshot)
        diagnostics.append({'case': 'private_' + field + '_redacted_on_visible_error_path',
                            'status': seen['decision'], 'private_value_absent_from_snapshot': True})
    guard = JointGuard(ledger, targets, query)
    row = copy.deepcopy(points['masked']); row['private_diagnostic'] = 73499
    seen = guard.observe('point', row)
    assert seen['decision'] == 'VISIBLE_SOURCE_LANGUAGE_FAILURE'
    assert '73499' not in json.dumps(guard.snapshot())
    try:
        guard.preflight_points([])
    except ValueError:
        pass
    else:
        raise AssertionError('An unmodeled visible event was silently dropped from future admission')
    diagnostics.append({'case': 'unknown_private_field_redacted_history_unresolved',
                        'status': seen['decision'], 'future_admission_uncertified': True})
    guard = JointGuard(ledger, targets, query)
    row = copy.deepcopy(scalar)
    row.update(observer_available=False, rhs=90071, ordinary={'v': 90073})
    seen = guard.observe('scalar', row)
    assert seen['decision'] == 'VISIBLE_SOURCE_LANGUAGE_FAILURE'
    encoded = json.dumps(guard.snapshot())
    assert '90071' not in encoded and '90073' not in encoded
    diagnostics.append({'case': 'whole_unavailable_observation_redacted',
                        'status': seen['decision'], 'private_rhs_and_coefficients_absent': True})
    out = {'schema': 'CHARE_JOINT_GUARD_RESULTS_V1', 'native_replay_verified': False,
           'scope': 'Independent coefficient reference; fixed-pair qualification contract; point-only prospective plans',
           'input_ledger': ledger, 'original_targets': targets, 'fact_query': query,
           'matrix_cases': matrix, 'history_diagnostics': diagnostics,
           'counts': {'matrix_cases': len(matrix), 'history_diagnostics': len(diagnostics)}}
    (HERE / 'joint_guard_results.json').write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps(out['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
