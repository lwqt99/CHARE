"""Exact coefficient reference for CHARE qualification compatibility.

This new increment imports the hash-pinned round-2 linear algebra.  It does not
implement a generic-group simulator, native curve operations, or RO replay.
Every common-prefix/availability assertion is an input contract, not a proof
that the supplied cryptographic record was honestly generated.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prior_runtime import load_auditor

_algebra = load_auditor()


class FactAuditError(ValueError):
    """Malformed input, unsupported model contract, or invalid evidence."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _integer(value, description):
    if not isinstance(value, int) or isinstance(value, bool):
        raise FactAuditError(f'{description} must be an integer')
    return value


def _prime64(p):
    if not isinstance(p, int) or isinstance(p, bool) or not 2 <= p < 2**64:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if p % small == 0:
            return p == small
    d, s = p - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % p == 0:
            continue
        x = pow(a, d, p)
        if x in (1, p - 1):
            continue
        for _ in range(s - 1):
            x = x * x % p
            if x == p - 1:
                break
        else:
            return False
    return True


def poly_trim(poly, p):
    out = [_integer(c, 'Polynomial coefficient') % p for c in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out or [0]


def poly_add(a, b, p):
    return poly_trim([(a[i] if i < len(a) else 0) +
                      (b[i] if i < len(b) else 0)
                      for i in range(max(len(a), len(b)))], p)


def poly_scale(a, c, p):
    return poly_trim([c * x % p for x in a], p)


def poly_mul(a, b, p):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % p
    return poly_trim(out, p)


def poly_eval(poly, x, p):
    out = 0
    for c in reversed(poly):
        out = (out * x + c) % p
    return out


def divide_linear(poly, node, p):
    """Return residue u and quotient q with poly=u+(X-node)q, exactly."""
    poly = poly_trim(poly, p)
    if len(poly) == 1:
        return poly[0], [0]
    quotient = [0] * (len(poly) - 1)
    quotient[-1] = poly[-1]
    for k in range(len(quotient) - 2, -1, -1):
        quotient[k] = (poly[k + 1] + node * quotient[k + 1]) % p
    residue = (poly[0] + node * quotient[0]) % p
    return residue, poly_trim(quotient, p)


def _vector(value, dimension, p, description):
    value = list(value)
    if len(value) != dimension:
        raise FactAuditError(f'{description}: expected {dimension} coordinates')
    return [_integer(x, description) % p for x in value]


def _id(value, description):
    if not isinstance(value, str) or not value:
        raise FactAuditError(f'{description} must be a nonempty string')
    return value


def _public_contract(row):
    if row.get('world_invariant') is not True:
        raise FactAuditError('UNSUPPORTED_MODEL: coefficients and affine offsets must be world-invariant on the common public prefix')
    _id(row.get('provenance'), 'Common-prefix provenance')


@dataclass(frozen=True)
class FactProblem:
    p: int
    setup_id: str
    setup_nodes: tuple[int, ...]
    fact_ids: tuple[str, ...]
    sources: tuple[dict, ...]
    pads: tuple[dict, ...]
    aliases: dict[str, str]
    scalars: tuple[dict, ...]
    points: tuple[dict, ...]
    factual_openings: tuple[dict, ...]
    public_powers_available: bool
    A: list[list[int]]
    Lw: list[list[int]]
    Lr: list[list[int]]
    P: list[list[list[int]]]
    B: list[list[int]]
    U: dict[int, list[list[int]]]
    Q: list[list[list[int]]]
    T: list[list[int]]
    G: dict[int, list[list[int]]]
    Gcirc: list[list[list[int]]]
    left_kernel: list[list[int]]
    ledger_digest: str

    @property
    def source_order(self):
        return [s['source_id'] for s in self.sources]

    @property
    def pad_order(self):
        return [s['source_id'] for s in self.pads]

    @property
    def N(self):
        return len(self.setup_nodes)


def compile_ledger(raw: dict[str, Any]) -> FactProblem:
    """Normalize identities and construct U_i,Q_k,T,G_i,Gcirc_k,H.

    Polynomials use ascending powers.  Alias keys do not create independent
    source coordinates or new fact-map rows.  Private offsets/RHS must be None;
    this interface never imports an instrumented private numerical value.
    """
    if raw.get('schema', 'CHARE_FACT_LEDGER_V1') != 'CHARE_FACT_LEDGER_V1':
        raise FactAuditError('Unsupported ledger schema')
    p = raw.get('p')
    if not _prime64(p):
        raise FactAuditError('The reference requires a prime field below 2^64')
    nodes = tuple(raw.get('setup_nodes', []))
    if not nodes or any(not isinstance(t, int) or isinstance(t, bool) or not 0 < t < p for t in nodes):
        raise FactAuditError('Setup nodes must be canonical nonzero field elements')
    if len(set(nodes)) != len(nodes) or len(nodes) >= p - 1:
        raise FactAuditError('Setup nodes must be distinct and leave an admissible tau')
    N = len(nodes)
    facts = tuple(_id(x, 'Fact ID') for x in raw.get('fact_ids', []))
    if not facts or len(set(facts)) != len(facts):
        raise FactAuditError('At least one distinct fact ID is required')
    f = len(facts)
    all_ids, slot_nodes = set(), {}
    sources, pads = [], []
    for supplied in raw.get('sources', []):
        sid = _id(supplied.get('source_id'), 'Ordinary source ID')
        if sid in all_ids:
            raise FactAuditError('A source ID cannot be redefined')
        all_ids.add(sid)
        kind = supplied.get('kind')
        if kind not in ('core', 'service_core', 'mask'):
            raise FactAuditError('Ordinary source kind must be core, service_core, or mask')
        node = _integer(supplied.get('node'), 'Source node')
        if node not in nodes:
            raise FactAuditError('Source node is not in the declared setup')
        slot = _id(supplied.get('slot'), 'Source slot')
        if slot in slot_nodes and slot_nodes[slot] != node:
            raise FactAuditError('One immutable slot cannot change its node')
        slot_nodes[slot] = node
        fact_map = _vector(supplied.get('fact_map', []), f, p, 'Fact-map row')
        if kind in ('core', 'service_core') and any(fact_map):
            raise FactAuditError('Core fact-map rows must be zero')
        cp = supplied.get('canonical_point', {})
        available = cp.get('available') is True
        handle = cp.get('handle_id')
        if handle is not None:
            _id(handle, 'Canonical point handle ID')
        if available:
            _id(handle, 'Available canonical point handle ID')
            _id(cp.get('provenance'), 'Canonical point provenance')
        sources.append({'source_id': sid, 'kind': kind, 'slot': slot, 'node': node,
                        'generation': _id(supplied.get('generation'), 'Source generation'),
                        'fact_map': fact_map,
                        'canonical_point': {'handle_id': handle, 'available': available,
                                            'provenance': cp.get('provenance', '')}})
    for supplied in raw.get('pads', []):
        sid = _id(supplied.get('source_id'), 'Pad source ID')
        if sid in all_ids:
            raise FactAuditError('A source ID cannot be redefined')
        all_ids.add(sid)
        pads.append({'source_id': sid,
                     'generation': _id(supplied.get('generation'), 'Pad generation')})
    alias_input = dict(raw.get('aliases', {}))
    if any(alias in all_ids for alias in alias_input):
        raise FactAuditError('An alias cannot replace an immutable source ID')
    aliases = {}
    def resolve(name):
        name = _id(name, 'Coefficient source ID')
        seen = set()
        while name in alias_input:
            if name in seen:
                raise FactAuditError('Cyclic source aliases')
            seen.add(name)
            name = _id(alias_input[name], 'Alias target')
        if name not in all_ids:
            raise FactAuditError(f'Unknown source ID: {name}')
        return name
    for alias in alias_input:
        aliases[_id(alias, 'Alias')] = resolve(alias)
    source_order, pad_order = [s['source_id'] for s in sources], [s['source_id'] for s in pads]
    ns, nr = len(source_order), len(pad_order)
    def coefficients(mapping, ordinary, polynomial):
        order = source_order if ordinary else pad_order
        result = [[0] for _ in order] if polynomial else [0] * len(order)
        for alias, value in mapping.items():
            sid = resolve(alias)
            if sid not in order:
                raise FactAuditError('An ordinary/pad coefficient uses the wrong kind of source')
            j = order.index(sid)
            if polynomial:
                value = poly_trim(value, p)
                if len(value) > N:
                    raise FactAuditError('Point polynomial degree exceeds N-1')
                result[j] = poly_add(result[j], value, p)
            else:
                result[j] = (result[j] + _integer(value, 'Scalar coefficient')) % p
        return result
    scalars, points, observation_ids = [], [], set()
    for kind, entries in (('scalar', raw.get('scalars', [])), ('point', raw.get('points', []))):
        for supplied in entries:
            _public_contract(supplied)
            oid = _id(supplied.get('observation_id'), 'Observation ID')
            if oid in observation_ids:
                raise FactAuditError('Observation IDs must be distinct')
            observation_ids.add(oid)
            offset_available = supplied.get('offset_available', True) is True
            offset = supplied.get('offset')
            if not offset_available and offset is not None:
                raise FactAuditError('Private affine offsets must be None, not an instrumented secret value')
            if offset_available:
                if kind == 'point':
                    offset = poly_trim(offset if offset is not None else [0], p)
                    if len(offset) > N:
                        raise FactAuditError('Point offset degree exceeds N-1')
                else:
                    offset = _integer(0 if offset is None else offset, 'Scalar offset') % p
            row = {'observation_id': oid,
                   'ordinary': coefficients(supplied.get('ordinary', {}), True, kind == 'point'),
                   'pads': coefficients(supplied.get('pads', {}), False, False),
                   'offset': offset, 'offset_available': offset_available,
                   'observer_available': supplied.get('observer_available', True) is True,
                   'world_invariant': True, 'provenance': supplied['provenance']}
            if kind == 'scalar':
                rhs_available = supplied.get('rhs_available', True) is True
                rhs = supplied.get('rhs')
                if not rhs_available and rhs is not None:
                    raise FactAuditError('A private scalar RHS must be None')
                if rhs_available:
                    rhs = _integer(rhs, 'Actual scalar RHS') % p
                row.update(rhs=rhs, rhs_available=rhs_available,
                           ell=(rhs - offset) % p if rhs_available and offset_available else None)
                scalars.append(row)
            else:
                handle = supplied.get('handle_id')
                if row['observer_available']:
                    _id(handle, 'Visible point handle ID')
                row['handle_id'] = handle
                points.append(row)
    openings, opening_ids = [], set()
    for supplied in raw.get('factual_openings', []):
        oid = _id(supplied.get('opening_id'), 'Factual opening ID')
        if oid in opening_ids:
            raise FactAuditError('Factual opening IDs must be distinct')
        opening_ids.add(oid)
        openings.append({'opening_id': oid,
                         'coefficients': _vector(supplied.get('coefficients', []), f, p, 'Factual opening'),
                         'rhs': _integer(supplied.get('rhs'), 'Factual RHS') % p,
                         'provenance': _id(supplied.get('provenance'), 'Factual opening provenance')})
    # Actual affine values are retained and checked for consistency.  Unknown
    # offsets/RHS do not become known equations merely because an analyst has them.
    known = [s for s in scalars if s['ell'] is not None]
    if _algebra.solve([s['ordinary'] + s['pads'] for s in known],
                      [s['ell'] for s in known], ns + nr, p) is None:
        raise FactAuditError('Actual public affine scalar answers have an empty fiber')
    A = [s['fact_map'] for s in sources]
    Lw, Lr = [s['ordinary'] for s in scalars], [s['pads'] for s in scalars]
    P, B = [s['ordinary'] for s in points], [s['pads'] for s in points]
    U = {node: [[0] * ns for _ in points] for node in nodes}
    Q = [[[0] * ns for _ in points] for _ in range(max(0, N - 1))]
    for m, row in enumerate(P):
        for a, poly in enumerate(row):
            u, quotient = divide_linear(poly, sources[a]['node'], p)
            U[sources[a]['node']][m][a] = u
            for k, c in enumerate(quotient):
                if k < len(Q):
                    Q[k][m][a] = c
                elif c:
                    raise FactAuditError('Internal polynomial degree inconsistency')
    def right_A(matrix):
        return [[sum(row[a] * A[a][j] for a in range(ns)) % p for j in range(f)] for row in matrix]
    G = {}
    for node in nodes:
        restricted = [[row[a] if sources[a]['node'] == node else 0 for a in range(ns)] for row in Lw]
        G[node] = right_A(restricted) + right_A(U[node])
    Gcirc = [[[0] * f for _ in scalars] + right_A(q) for q in Q]
    T = Lr + B
    H = _algebra.nullspace(_algebra.transpose(T, nr), len(T), p)
    normalized = {'p': p, 'setup_id': _id(raw.get('setup_id'), 'Setup ID'),
                  'setup_nodes': nodes, 'fact_ids': facts, 'sources': sources,
                  'pads': pads, 'aliases': aliases, 'scalars': scalars, 'points': points,
                  'factual_openings': openings,
                  'public_powers_available': raw.get('public_powers_available', True) is True}
    return FactProblem(p=p, setup_id=normalized['setup_id'], setup_nodes=nodes,
                       fact_ids=facts, sources=tuple(sources), pads=tuple(pads), aliases=aliases,
                       scalars=tuple(scalars), points=tuple(points), factual_openings=tuple(openings),
                       public_powers_available=normalized['public_powers_available'],
                       A=A, Lw=Lw, Lr=Lr, P=P, B=B, U=U, Q=Q, T=T, G=G, Gcirc=Gcirc,
                       left_kernel=H, ledger_digest=digest(normalized))


def describe_problem(problem: FactProblem):
    """Export only normalized input descriptors and formal matrices."""
    return {'schema': 'CHARE_FACT_PROBLEM_V1', 'ledger_digest': problem.ledger_digest,
            'p': problem.p, 'setup_id': problem.setup_id, 'setup_nodes': list(problem.setup_nodes),
            'fact_ids': list(problem.fact_ids), 'source_order': problem.source_order,
            'pad_order': problem.pad_order,
            'scalar_order': [s['observation_id'] for s in problem.scalars],
            'point_order': [s['observation_id'] for s in problem.points],
            'sources': list(problem.sources), 'pads': list(problem.pads), 'aliases': problem.aliases,
            'scalars': list(problem.scalars), 'points': list(problem.points),
            'factual_openings': list(problem.factual_openings),
            'A': problem.A, 'Lw': problem.Lw, 'Lr': problem.Lr, 'P': problem.P, 'B': problem.B,
            'U_by_node': {str(k): v for k, v in problem.U.items()}, 'Q_by_degree': problem.Q,
            'T': problem.T, 'G_by_node': {str(k): v for k, v in problem.G.items()},
            'Gcirc_by_degree': problem.Gcirc, 'left_kernel_basis': problem.left_kernel,
            'descriptor_generation_verified': False}


def verify_history_extension(previous: FactProblem, updated: FactProblem):
    """Check an append-only descriptor transition in the SAME fact basis.

    This is a coefficient/identity check, not authentication or proof that two
    equal handle IDs encode equal curve points.  Fact-basis changes require a
    separate displacement-preservation proof and are deliberately unsupported.
    """
    if (previous.p, previous.setup_id, previous.setup_nodes, previous.fact_ids) != \
       (updated.p, updated.setup_id, updated.setup_nodes, updated.fact_ids):
        raise FactAuditError('History changed setup or fact representation without a preservation proof')
    new_sources = {s['source_id']: s for s in updated.sources}
    for old in previous.sources:
        new = new_sources.get(old['source_id'])
        if new is None or any(old[k] != new[k] for k in ('kind', 'slot', 'node', 'generation', 'fact_map')):
            raise FactAuditError('History changed an immutable source or its original fact displacement')
        old_cp, new_cp = old['canonical_point'], new['canonical_point']
        if old_cp['handle_id'] is not None and old_cp['handle_id'] != new_cp['handle_id']:
            raise FactAuditError('History rebound an original canonical point handle')
        if old_cp['available'] and not new_cp['available']:
            raise FactAuditError('History removed an already available canonical point')
    if any(updated.aliases.get(k) != v for k, v in previous.aliases.items()):
        raise FactAuditError('History removed or rebound an original alias')
    for description, old_rows, new_rows, key in (
        ('pad', previous.pads, updated.pads, 'source_id'),
        ('scalar', previous.scalars, updated.scalars, 'observation_id'),
        ('point', previous.points, updated.points, 'observation_id'),
        ('factual opening', previous.factual_openings, updated.factual_openings, 'opening_id')):
        new_by_id = {r[key]: r for r in new_rows}
        for old in old_rows:
            new = new_by_id.get(old[key])
            if new is None:
                raise FactAuditError(f'History removed an already visible {description}')
            if description in ('point', 'scalar'):
                # New sources append zero coordinates to old observations;
                # compare their coefficients by immutable source identity.
                old_ordinary = dict(zip(previous.source_order, old['ordinary']))
                new_ordinary = dict(zip(updated.source_order, new['ordinary']))
                old_pad = dict(zip(previous.pad_order, old['pads']))
                new_pad = dict(zip(updated.pad_order, new['pads']))
                zero = [0] if description == 'point' else 0
                if any(new_ordinary.get(sid, zero) != old_ordinary.get(sid, zero)
                       for sid in set(old_ordinary) | set(new_ordinary)) or \
                   any(new_pad.get(sid, 0) != old_pad.get(sid, 0) for sid in set(old_pad) | set(new_pad)):
                    raise FactAuditError('History changed coefficients of an already visible observation')
                ignored = {'ordinary', 'pads'}
                if any(old[k] != new.get(k) for k in old if k not in ignored):
                    raise FactAuditError('History changed actual RHS, offsets, availability, or provenance of an old observation')
            elif old != new:
                raise FactAuditError(f'History changed an immutable {description}')
    if previous.public_powers_available and not updated.public_powers_available:
        raise FactAuditError('History removed already public setup powers')
    return {'verified': True, 'previous_ledger_digest': previous.ledger_digest,
            'updated_ledger_digest': updated.ledger_digest,
            'scope': 'Append-only coefficient and identity descriptors; no cryptographic generation/authentication verification'}


def _matvec(matrix, v, p):
    return [sum(x * y for x, y in zip(row, v)) % p for row in matrix]


def _denominator(problem):
    denominator = [1]
    for t in problem.setup_nodes:
        denominator = poly_mul(denominator, [-t, 1], problem.p)
    return denominator


def _rational_description(problem, f_polynomials, d):
    p = problem.p
    shifts = _matvec(problem.A, d, p)
    residues = {t: 0 for t in problem.setup_nodes}
    polynomial, numerator = [0], [0]
    denominator = _denominator(problem)
    for a, f_a in enumerate(f_polynomials):
        node = problem.sources[a]['node']
        residue, quotient = divide_linear(f_a, node, p)
        residues[node] = (residues[node] + residue * shifts[a]) % p
        polynomial = poly_add(polynomial, poly_scale(quotient, shifts[a], p), p)
        rem, denominator_without_node = divide_linear(denominator, node, p)
        if rem:
            raise FactAuditError('Internal denominator division failed')
        numerator = poly_add(numerator, poly_scale(poly_mul(f_a, denominator_without_node, p), shifts[a], p), p)
    return {'residues': [{'node': t, 'value': residues[t]} for t in problem.setup_nodes],
            'polynomial': polynomial, 'cleared_denominator_numerator': numerator,
            'denominator': denominator, 'formal_nonzero': any(numerator),
            'fixed_tau_evaluation': 'NOT_PERFORMED; a nonzero rational function may vanish at a legal tau'}


def _witness_recipe(problem, c, zeta, f_polynomials):
    p = problem.p
    required = []
    reasons = []
    for source, f_a in zip(problem.sources, f_polynomials):
        if any(f_a):
            cp = source['canonical_point']
            required.append({'source_id': source['source_id'], 'handle_id': cp['handle_id'],
                             'available': cp['available'], 'provenance': cp['provenance']})
            if not cp['available']:
                reasons.append({'kind': 'CANONICAL_POINT_UNAVAILABLE', 'source_id': source['source_id']})
    correction = [0]
    correction_available = True
    point_terms, scalar_terms = [], []
    for z, row in zip(zeta, problem.points):
        if not z:
            continue
        point_terms.append({'observation_id': row['observation_id'], 'handle_id': row['handle_id'],
                            'coefficient': z, 'offset_polynomial': row['offset'],
                            'offset_available': row['offset_available'],
                            'observer_available': row['observer_available']})
        if not row['observer_available']:
            reasons.append({'kind': 'POINT_HANDLE_UNAVAILABLE', 'observation_id': row['observation_id']})
        if row['offset_available']:
            correction = poly_add(correction, poly_scale(row['offset'], -z, p), p)
        else:
            correction_available = False
            reasons.append({'kind': 'AFFINE_OFFSET_UNAVAILABLE', 'observation_id': row['observation_id']})
    for coefficient, row in zip(c, problem.scalars):
        if not coefficient:
            continue
        scalar_terms.append({'observation_id': row['observation_id'], 'coefficient': coefficient,
                             'actual_rhs': row['rhs'], 'offset': row['offset'], 'ell': row['ell'],
                             'observer_available': row['observer_available'],
                             'rhs_available': row['rhs_available'], 'offset_available': row['offset_available'],
                             'provenance': row['provenance']})
        if not row['observer_available'] or not row['rhs_available']:
            reasons.append({'kind': 'ACTUAL_SCALAR_ANSWER_UNAVAILABLE', 'observation_id': row['observation_id']})
        if not row['offset_available']:
            reasons.append({'kind': 'AFFINE_OFFSET_UNAVAILABLE', 'observation_id': row['observation_id']})
        if row['ell'] is None or not row['observer_available']:
            correction_available = False
        else:
            correction = poly_add(correction, [coefficient * row['ell'] % p], p)
    if not problem.public_powers_available:
        reasons.append({'kind': 'PUBLIC_POWERS_UNAVAILABLE'})
    return {'canonical_points_required': required,
            'canonical_point_ids_required': [x['handle_id'] for x in required],
            'point_terms': point_terms, 'scalar_terms': scalar_terms,
            'known_h_correction_polynomial': correction if correction_available else None,
            'h_correction_available': correction_available,
            'public_powers_available': problem.public_powers_available,
            'representation_prerequisites_present': not reasons, 'blocked_reasons': reasons,
            'scope': 'RETURNED_WITNESS_ONLY; no exhaustive search for alternative available witnesses',
            'formula': 'Cstar=sum(zeta_m*C_m)+(c*ell-sum(zeta_m*d_m(tau)))*h',
            'test_formula': 'e(g,Cstar)-sum_a e(E_a,f_a(tau)*h)',
            'native_replay_verified': False}


def _base_result(problem, d):
    public_model = all(r['observer_available'] and r['offset_available'] and
                       (r.get('rhs_available', True))
                       for r in list(problem.scalars) + list(problem.points))
    return {'schema': 'CHARE_FACT_EVIDENCE_V1', 'ledger_digest': problem.ledger_digest,
            'query_kind': 'difference', 'p': problem.p, 'difference': d,
            'source_order': problem.source_order, 'pad_order': problem.pad_order,
            'scalar_order': [s['observation_id'] for s in problem.scalars],
            'point_order': [s['observation_id'] for s in problem.points],
            'evidence_level': 'FINITE_FIELD_FORMAL', 'native_replay_verified': False,
            'history_contract_eligible': public_model,
            'model_scope': 'DECLARED_OBSERVER_SOURCE_LANGUAGE' if public_model else 'FORMAL_PRIVATE_DESCRIPTOR_ONLY',
            'pair_legality_verified': False,
            'factual_opening_difference_agreement': all(_algebra.dot(o['coefficients'], d, problem.p) == 0
                                                       for o in problem.factual_openings),
            'contract': 'World-invariant public-prefix coefficients/offsets and source bindings are supplied assertions, not generation proofs'}


def audit_difference(problem: FactProblem, difference):
    d = _vector(difference, len(problem.fact_ids), problem.p, 'Fact difference')
    out = _base_result(problem, d)
    components = [('pole', t, G) for t, G in problem.G.items()]
    components += [('polynomial', k, G) for k, G in enumerate(problem.Gcirc)]
    poles, polynomial = [], []
    for kind, index, G in components:
        rhs = _matvec(G, d, problem.p)
        preimage = _algebra.solve(problem.T, rhs, len(problem.pads), problem.p)
        if preimage is None:
            h = next(h for h in problem.left_kernel if _algebra.dot(h, rhs, problem.p))
            c, zeta = h[:len(problem.scalars)], h[len(problem.scalars):]
            f_polynomials = []
            for a in range(len(problem.sources)):
                f_a = [sum(c[j] * problem.Lw[j][a] for j in range(len(c))) % problem.p]
                for m, z in enumerate(zeta):
                    f_a = poly_add(f_a, poly_scale(problem.P[m][a], z, problem.p), problem.p)
                f_polynomials.append(f_a)
            component = {'kind': kind, 'value': _algebra.dot(h, rhs, problem.p)}
            component['node' if kind == 'pole' else 'degree'] = index
            recipe = _witness_recipe(problem, c, zeta, f_polynomials)
            out.update(formal_status='INCOMPATIBLE', execution_status='DIRECTION_ONLY',
                       witness={'c': c, 'zeta': zeta, 'left_kernel_row': h,
                                'failed_component': component, 'f_polynomials': f_polynomials,
                                'rational_difference': _rational_description(problem, f_polynomials, d),
                                **recipe}, witness_search_scope='FIRST_FAILED_LEFT_KERNEL_BASIS_ROW')
            verify_evidence(problem, out)
            out['algebraic_verification'] = True
            return out
        item = {'node' if kind == 'pole' else 'degree': index, 'vector': preimage, 'rhs': rhs}
        (poles if kind == 'pole' else polynomial).append(item)
    out.update(formal_status='COMPATIBLE', execution_status='NO_DISTINGUISHING_WITNESS',
               certificate={'pole_preimages': poles, 'polynomial_preimages': polynomial,
                            'pad_shift_formula': 'Delta_r=-beta*(sum_i v_i/(tau-t_i)+sum_k vcirc_k*tau**k)'})
    verify_evidence(problem, out)
    out['algebraic_verification'] = True
    return out


def _pair_contract_ok(contract):
    return isinstance(contract, dict) and all(contract.get(k) is True for k in (
        'legal_pair', 'same_public_metadata_and_outcomes', 'fixed_before_fresh_sources')) and bool(contract.get('provenance'))


def audit_pair(problem: FactProblem, y0, y1, pair_contract=None):
    y0 = _vector(y0, len(problem.fact_ids), problem.p, 'Assignment y0')
    y1 = _vector(y1, len(problem.fact_ids), problem.p, 'Assignment y1')
    out = audit_difference(problem, [(b - a) % problem.p for a, b in zip(y0, y1)])
    out['query_kind'], out['y0'], out['y1'] = 'fixed_pair', y0, y1
    contract_ok = _pair_contract_ok(pair_contract)
    # The flag documents a caller assertion; this reference cannot verify an
    # application's legal-history relation or precommitment independently.
    out['pair_contract_supplied'] = contract_ok
    out['pair_contract'] = pair_contract if contract_ok else None
    openings_ok = all(_algebra.dot(row['coefficients'], y, problem.p) == row['rhs']
                      for row in problem.factual_openings for y in (y0, y1))
    out['actual_factual_openings_match_both'] = openings_ok
    out['pair_status'] = ('PAIR_CONTRACT_FAILED' if not openings_ok else
                          'CONDITIONAL_LEGAL_PAIR' if contract_ok else 'PAIR_CONTRACT_UNVERIFIED')
    if out['formal_status'] == 'INCOMPATIBLE':
        if not openings_ok:
            out['execution_status'] = 'PAIR_CONTRACT_FAILED'
        elif not contract_ok:
            out['execution_status'] = 'PAIR_CONTRACT_UNVERIFIED'
        elif out['witness']['representation_prerequisites_present']:
            out['execution_status'] = 'PAIRING_TEST_RECIPE_READY'
        elif any(r['kind'] == 'CANONICAL_POINT_UNAVAILABLE' for r in out['witness']['blocked_reasons']):
            out['execution_status'] = 'PENDING_CANONICAL_POINTS'
        else:
            out['execution_status'] = 'REPRESENTATION_PREREQUISITES_MISSING'
    verify_evidence(problem, out)
    return out


def audit_span(problem: FactProblem, difference_vectors, span_relation='exact', actual_pairs=None):
    """Test a supplied difference span; basis vectors are not legal fact pairs.

    actual_pairs, if supplied, is a list of {pair_id,y0,y1,pair_contract}.
    Exact requires its differences to span exactly the supplied space.  A
    superset failure alone never asserts an incompatible actual legal pair.
    """
    if span_relation not in ('exact', 'superset'):
        raise FactAuditError('span_relation must be exact or superset')
    vectors = [_vector(d, len(problem.fact_ids), problem.p, 'Difference-span generator') for d in difference_vectors]
    basis = _algebra.RowSpace(vectors, len(problem.fact_ids), problem.p)
    basis_results = [audit_difference(problem, d) for d in basis.rows]
    pair_results, pair_differences, pair_ids = [], [], set()
    for supplied in actual_pairs or []:
        result = audit_pair(problem, supplied['y0'], supplied['y1'], supplied.get('pair_contract'))
        if not basis.contains(result['difference']):
            raise FactAuditError('An actual pair difference is outside the supplied family span')
        pair_id = _id(supplied.get('pair_id'), 'Pair ID')
        if pair_id in pair_ids:
            raise FactAuditError('Actual pair IDs must be distinct')
        pair_ids.add(pair_id)
        pair_differences.append(result['difference'])
        pair_results.append({'pair_id': pair_id, 'result': result})
    if actual_pairs is not None and span_relation == 'exact':
        pair_space = _algebra.RowSpace(pair_differences, len(problem.fact_ids), problem.p)
        if pair_space.rank != basis.rank:
            raise FactAuditError('Actual pair differences do not generate the claimed exact span')
    formal_ok = all(r['formal_status'] == 'COMPATIBLE' for r in basis_results)
    opening_ok = all(r['factual_opening_difference_agreement'] for r in basis_results)
    out = {'schema': 'CHARE_FACT_SPAN_EVIDENCE_V1', 'query_kind': 'difference_span',
           'ledger_digest': problem.ledger_digest, 'p': problem.p, 'span_relation': span_relation,
           'actual_pairs_supplied': actual_pairs is not None,
           'input_difference_vectors': vectors, 'basis_vectors': basis.rows,
           'basis_results': basis_results, 'actual_pair_results': pair_results,
           'formal_status': 'COMPATIBLE' if formal_ok else 'INCOMPATIBLE_DIRECTION',
           'family_status': ('COMPATIBLE_EXACT_SPAN' if span_relation == 'exact' else 'COMPATIBLE_SUPERSET') if formal_ok and opening_ok
                            else ('UNCERTIFIED_SUPERSET' if span_relation == 'superset' else 'INCOMPATIBLE_OR_OPENING_MISMATCH_SPAN'),
           'actual_pair_failure_ids': [x['pair_id'] for x in pair_results
                                      if x['result']['formal_status'] == 'INCOMPATIBLE' and
                                      x['result']['pair_status'] == 'CONDITIONAL_LEGAL_PAIR'],
           'evidence_level': 'FINITE_FIELD_FORMAL', 'native_replay_verified': False,
           'execution_status': 'SEE_EXPLICIT_PAIR_RESULTS_ONLY',
           'scope': 'The supplied span relation is a caller contract; an incompatible basis direction is not itself a legal fact pair'}
    verify_evidence(problem, out)
    out['algebraic_verification'] = True
    return out


def verify_evidence(problem: FactProblem, result):
    """Check returned evidence without running the compatibility solver.

    Compatible evidence is checked by clearing denominators in the ORIGINAL
    observation polynomials, not just by repeating the constructed G tests.
    Incompatible evidence is checked directly from c,zeta and the originals.
    """
    p = problem.p
    if result.get('ledger_digest') != problem.ledger_digest:
        raise FactAuditError('Evidence belongs to a different ledger')
    if result.get('p') != p or result.get('evidence_level') != 'FINITE_FIELD_FORMAL':
        raise FactAuditError('Evidence changed its field or formal evidence level')
    if result.get('query_kind') not in ('difference', 'fixed_pair', 'difference_span'):
        raise FactAuditError('Unknown evidence query kind')
    if result.get('query_kind') == 'difference_span':
        if result.get('schema') != 'CHARE_FACT_SPAN_EVIDENCE_V1':
            raise FactAuditError('Wrong family evidence schema')
        if result.get('span_relation') not in ('exact', 'superset'):
            raise FactAuditError('Unknown verified span relation')
        basis = _algebra.RowSpace(result['basis_vectors'], len(problem.fact_ids), p)
        inputs = _algebra.RowSpace(result['input_difference_vectors'], len(problem.fact_ids), p)
        if basis.rank != inputs.rank or any(not inputs.contains(r) for r in basis.rows):
            raise FactAuditError('Span certificate changed the input space')
        if len(result['basis_results']) != len(result['basis_vectors']):
            raise FactAuditError('Missing basis evidence')
        for d, child in zip(result['basis_vectors'], result['basis_results']):
            if child['difference'] != d:
                raise FactAuditError('Basis evidence uses a different direction')
            verify_evidence(problem, child)
        pair_ids, pair_differences = set(), []
        for entry in result['actual_pair_results']:
            if entry['pair_id'] in pair_ids:
                raise FactAuditError('Repeated pair identity in span evidence')
            pair_ids.add(entry['pair_id'])
            verify_evidence(problem, entry['result'])
            pair_differences.append(entry['result']['difference'])
            if not basis.contains(entry['result']['difference']):
                raise FactAuditError('Actual pair outside verified span')
        expected = 'COMPATIBLE' if all(r['formal_status'] == 'COMPATIBLE' for r in result['basis_results']) else 'INCOMPATIBLE_DIRECTION'
        if result['formal_status'] != expected:
            raise FactAuditError('Incorrect aggregate formal status')
        if result.get('actual_pairs_supplied') is False and result['actual_pair_results']:
            raise FactAuditError('Span evidence has undeclared actual pairs')
        if result.get('actual_pairs_supplied') is True and result['span_relation'] == 'exact':
            if _algebra.RowSpace(pair_differences, len(problem.fact_ids), p).rank != basis.rank:
                raise FactAuditError('Actual pair differences do not generate the verified exact span')
        if not isinstance(result.get('actual_pairs_supplied'), bool):
            raise FactAuditError('Missing actual-pair presence flag')
        openings_ok = all(r['factual_opening_difference_agreement'] for r in result['basis_results'])
        expected_family = (('COMPATIBLE_EXACT_SPAN' if result['span_relation'] == 'exact' else 'COMPATIBLE_SUPERSET')
                           if expected == 'COMPATIBLE' and openings_ok else
                           ('UNCERTIFIED_SUPERSET' if result['span_relation'] == 'superset' else 'INCOMPATIBLE_OR_OPENING_MISMATCH_SPAN'))
        expected_failure_ids = [entry['pair_id'] for entry in result['actual_pair_results']
                                if entry['result']['formal_status'] == 'INCOMPATIBLE' and
                                entry['result']['pair_status'] == 'CONDITIONAL_LEGAL_PAIR']
        if result.get('family_status') != expected_family or result.get('actual_pair_failure_ids') != expected_failure_ids:
            raise FactAuditError('Span evidence misreports family compatibility or an actual pair failure')
        if result.get('execution_status') != 'SEE_EXPLICIT_PAIR_RESULTS_ONLY':
            raise FactAuditError('A basis direction cannot assert an executable fixed-pair distinction')
        if result.get('native_replay_verified') is not False:
            raise FactAuditError('The coefficient module cannot certify a native replay')
        return True
    d = _vector(result.get('difference', []), len(problem.fact_ids), p, 'Evidence difference')
    if result.get('schema') != 'CHARE_FACT_EVIDENCE_V1' or result.get('pair_legality_verified') is not False:
        raise FactAuditError('The coefficient module cannot certify pair legality')
    if result.get('source_order') != problem.source_order or result.get('pad_order') != problem.pad_order:
        raise FactAuditError('Evidence changed source identity order')
    if result.get('scalar_order') != [r['observation_id'] for r in problem.scalars] or \
       result.get('point_order') != [r['observation_id'] for r in problem.points]:
        raise FactAuditError('Evidence changed the original observation order')
    for key in ('factual_opening_difference_agreement', 'history_contract_eligible', 'model_scope'):
        if result.get(key) != _base_result(problem, d)[key]:
            raise FactAuditError('Evidence misreports the observation or factual-opening contract')
    if result.get('query_kind') == 'fixed_pair':
        y0, y1 = result['y0'], result['y1']
        if d != [(b - a) % p for a, b in zip(y0, y1)]:
            raise FactAuditError('Pair evidence has the wrong difference')
    if result.get('formal_status') == 'COMPATIBLE':
        certificate = result['certificate']
        poles, polynomials = certificate['pole_preimages'], certificate['polynomial_preimages']
        if [x['node'] for x in poles] != list(problem.setup_nodes):
            raise FactAuditError('Missing or reordered pole preimages')
        if [x['degree'] for x in polynomials] != list(range(max(0, problem.N - 1))):
            raise FactAuditError('Missing or reordered polynomial preimages')
        denominator = _denominator(problem)
        pad_numerators = [[0] for _ in problem.pads]
        for item in poles:
            v = _vector(item['vector'], len(problem.pads), p, 'Pad preimage')
            rem, complement = divide_linear(denominator, item['node'], p)
            if rem:
                raise FactAuditError('Pole does not divide denominator')
            rhs = _matvec(problem.G[item['node']], d, p)
            if _matvec(problem.T, v, p) != rhs or item['rhs'] != rhs:
                raise FactAuditError('Incorrect pole pad preimage')
            for j in range(len(v)):
                pad_numerators[j] = poly_add(pad_numerators[j], poly_scale(complement, v[j], p), p)
        for item in polynomials:
            v = _vector(item['vector'], len(problem.pads), p, 'Polynomial pad preimage')
            rhs = _matvec(problem.Gcirc[item['degree']], d, p)
            if _matvec(problem.T, v, p) != rhs or item['rhs'] != rhs:
                raise FactAuditError('Incorrect polynomial pad preimage')
            term = [0] * item['degree'] + denominator
            for j in range(len(v)):
                pad_numerators[j] = poly_add(pad_numerators[j], poly_scale(term, v[j], p), p)
        rows = [[[x] for x in row] for row in problem.Lw] + problem.P
        for index, original_coefficients in enumerate(rows):
            original = _rational_description(problem, original_coefficients, d)['cleared_denominator_numerator']
            reconstructed = [0]
            for coeff, numerator in zip(problem.T[index], pad_numerators):
                reconstructed = poly_add(reconstructed, poly_scale(numerator, coeff, p), p)
            if original != reconstructed:
                raise FactAuditError('Pad shift fails the original cleared-denominator identity')
    elif result.get('formal_status') == 'INCOMPATIBLE':
        witness = result['witness']
        c = _vector(witness['c'], len(problem.scalars), p, 'Left-kernel scalar row')
        zeta = _vector(witness['zeta'], len(problem.points), p, 'Left-kernel point row')
        h = c + zeta
        if witness['left_kernel_row'] != h:
            raise FactAuditError('Left-kernel row does not match c,zeta')
        if any(sum(h[i] * problem.T[i][j] for i in range(len(h))) % p for j in range(len(problem.pads))):
            raise FactAuditError('Witness does not cancel the joint pads')
        f_polynomials = []
        for a in range(len(problem.sources)):
            f_a = [sum(c[j] * problem.Lw[j][a] for j in range(len(c))) % p]
            for m, z in enumerate(zeta):
                f_a = poly_add(f_a, poly_scale(problem.P[m][a], z, p), p)
            f_polynomials.append(f_a)
        if witness['f_polynomials'] != f_polynomials:
            raise FactAuditError('Incorrect polynomial coefficients in the distinguishing recipe')
        rational = _rational_description(problem, f_polynomials, d)
        if not rational['formal_nonzero'] or rational != witness['rational_difference']:
            raise FactAuditError('Witness rational difference is zero or misreported')
        component = witness['failed_component']
        if component['kind'] == 'pole':
            expected = next(x['value'] for x in rational['residues'] if x['node'] == component['node'])
        elif component['kind'] == 'polynomial':
            k = component['degree']
            expected = rational['polynomial'][k] if 0 <= k < len(rational['polynomial']) else 0
        else:
            raise FactAuditError('Unsupported failure component')
        if not expected or component['value'] != expected:
            raise FactAuditError('Witness failure component is not nonzero')
        recipe = _witness_recipe(problem, c, zeta, f_polynomials)
        if any(witness.get(k) != v for k, v in recipe.items()):
            raise FactAuditError('Witness representation prerequisites or affine recipe are incorrect')
    else:
        raise FactAuditError('Unsupported formal evidence status')
    if result.get('native_replay_verified') is not False:
        raise FactAuditError('The coefficient module cannot certify a native replay')
    expected_execution = 'NO_DISTINGUISHING_WITNESS'
    if result.get('query_kind') == 'fixed_pair':
        y0 = _vector(result['y0'], len(problem.fact_ids), p, 'Assignment y0')
        y1 = _vector(result['y1'], len(problem.fact_ids), p, 'Assignment y1')
        openings_ok = all(_algebra.dot(row['coefficients'], y, p) == row['rhs']
                          for row in problem.factual_openings for y in (y0, y1))
        contract_ok = _pair_contract_ok(result.get('pair_contract'))
        expected_pair = ('PAIR_CONTRACT_FAILED' if not openings_ok else
                         'CONDITIONAL_LEGAL_PAIR' if contract_ok else 'PAIR_CONTRACT_UNVERIFIED')
        if result.get('pair_status') != expected_pair or result.get('actual_factual_openings_match_both') != openings_ok or \
           result.get('pair_contract_supplied') != contract_ok:
            raise FactAuditError('Evidence misreports fixed-pair contractual prerequisites')
        if result['formal_status'] == 'INCOMPATIBLE':
            if not openings_ok:
                expected_execution = 'PAIR_CONTRACT_FAILED'
            elif not contract_ok:
                expected_execution = 'PAIR_CONTRACT_UNVERIFIED'
            elif result['witness']['representation_prerequisites_present']:
                expected_execution = 'PAIRING_TEST_RECIPE_READY'
            elif any(r['kind'] == 'CANONICAL_POINT_UNAVAILABLE' for r in result['witness']['blocked_reasons']):
                expected_execution = 'PENDING_CANONICAL_POINTS'
            else:
                expected_execution = 'REPRESENTATION_PREREQUISITES_MISSING'
    elif result['formal_status'] == 'INCOMPATIBLE':
        expected_execution = 'DIRECTION_ONLY'
    if result.get('execution_status') != expected_execution:
        raise FactAuditError('Evidence overstates or misreports executable distinguishing status')
    return True


def instantiate_pad_shift(problem: FactProblem, result, tau, beta=1):
    """Offline coefficient diagnostic at a supplied tau; not a public operation."""
    verify_evidence(problem, result)
    if result['formal_status'] != 'COMPATIBLE':
        raise FactAuditError('Only compatible evidence supplies a pad shift')
    if not 0 < tau < problem.p or tau in problem.setup_nodes:
        raise FactAuditError('Tau is not admissible')
    value = [0] * len(problem.pads)
    for item in result['certificate']['pole_preimages']:
        factor = pow((tau - item['node']) % problem.p, -1, problem.p)
        for j, coefficient in enumerate(item['vector']):
            value[j] = (value[j] - beta * factor * coefficient) % problem.p
    for item in result['certificate']['polynomial_preimages']:
        factor = pow(tau, item['degree'], problem.p)
        for j, coefficient in enumerate(item['vector']):
            value[j] = (value[j] - beta * factor * coefficient) % problem.p
    return value


def evaluate_rational_witness(problem: FactProblem, result, tau, beta=1):
    """Return a fixed-tau model value, without claiming an executed pairing."""
    verify_evidence(problem, result)
    if result['formal_status'] != 'INCOMPATIBLE':
        raise FactAuditError('No incompatible rational witness')
    if not 0 < tau < problem.p or tau in problem.setup_nodes:
        raise FactAuditError('Tau is not admissible')
    rational = result['witness']['rational_difference']
    numerator = poly_eval(rational['cleared_denominator_numerator'], tau, problem.p)
    denominator = poly_eval(rational['denominator'], tau, problem.p)
    value = beta * numerator * pow(denominator, -1, problem.p) % problem.p
    return {'evidence_level': 'EXPONENT_MODEL_IDENTITY_ONLY', 'tau': tau, 'beta': beta % problem.p,
            'rational_difference_value': value, 'fixed_tau_collision': value == 0,
            'formal_nonzero': True, 'native_replay_verified': False}
