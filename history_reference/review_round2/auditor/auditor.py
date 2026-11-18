"""CHARE finite-field reference auditor: coefficient diagnostics, no group replay.

The source descriptors and provenance are inputs. This module does not infer
secret coefficients from cryptographic encodings or verify honest generation.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict, replace
from itertools import combinations
from typing import Any
import copy
import hashlib
import json


class LedgerError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()


def dot(a, b, p):
    return sum(x * y for x, y in zip(a, b)) % p


def combination(coefficients, rows, n, p):
    return [sum(c * row[j] for c, row in zip(coefficients, rows)) % p for j in range(n)]


def transpose(rows, n):
    return [[row[j] for row in rows] for j in range(n)]


class RowSpace:
    """Small exact RREF basis over a prime field; insertion is O(d^2)."""
    def __init__(self, rows=(), dimension=0, p=101):
        self.dimension, self.p = dimension, p
        self.rows, self.pivots = [], []
        for row in rows:
            self.insert(row)

    def copy(self):
        out = RowSpace(dimension=self.dimension, p=self.p)
        out.rows = [r[:] for r in self.rows]
        out.pivots = self.pivots[:]
        return out

    def remainder(self, row):
        if len(row) != self.dimension:
            raise LedgerError('Vector dimension differs from the source registry')
        v = [x % self.p for x in row]
        for pivot, basis in zip(self.pivots, self.rows):
            c = v[pivot]
            if c:
                v = [(x - c * y) % self.p for x, y in zip(v, basis)]
        return v

    def contains(self, row):
        return not any(self.remainder(row))

    def insert(self, row):
        v = self.remainder(row)
        if not any(v):
            return False
        j = next(i for i, x in enumerate(v) if x)
        inverse = pow(v[j], -1, self.p)
        v = [x * inverse % self.p for x in v]
        for i, old in enumerate(self.rows):
            if old[j]:
                c = old[j]
                self.rows[i] = [(x - c * y) % self.p for x, y in zip(old, v)]
        index = sum(x < j for x in self.pivots)
        self.pivots.insert(index, j)
        self.rows.insert(index, v)
        return True

    @property
    def rank(self):
        return len(self.rows)


def solve(matrix, rhs, n, p):
    """Return one solution with free coordinates zero, or None."""
    if len(matrix) != len(rhs):
        raise LedgerError('Linear system row/RHS lengths differ')
    a = [[x % p for x in row] + [b % p] for row, b in zip(matrix, rhs)]
    if any(len(row) != n + 1 for row in a):
        raise LedgerError('Linear system column count differs')
    pivots, rank = [], 0
    for j in range(n):
        found = next((i for i in range(rank, len(a)) if a[i][j]), None)
        if found is None:
            continue
        a[rank], a[found] = a[found], a[rank]
        inverse = pow(a[rank][j], -1, p)
        a[rank] = [x * inverse % p for x in a[rank]]
        for i in range(len(a)):
            if i != rank and a[i][j]:
                c = a[i][j]
                a[i] = [(x - c * y) % p for x, y in zip(a[i], a[rank])]
        pivots.append(j)
        rank += 1
        if rank == len(a):
            break
    if any(not any(row[:n]) and row[n] for row in a):
        return None
    x = [0] * n
    for i, j in enumerate(pivots):
        x[j] = a[i][n]
    return x


def nullspace(rows, n, p):
    basis = RowSpace(rows, n, p)
    free = [j for j in range(n) if j not in basis.pivots]
    out = []
    for j in free:
        v = [0] * n
        v[j] = 1
        for pivot, row in zip(basis.pivots, basis.rows):
            v[pivot] = -row[j] % p
        out.append(v)
    return out


def lagrange_gamma(nodes, p):
    if any(not isinstance(node, int) or not (0 < node < p) for node in nodes):
        raise LedgerError('Nodes must use distinct canonical nonzero field representatives')
    if len(set(nodes)) != len(nodes):
        raise LedgerError('Target nodes must be distinct')
    out = []
    for i, ti in enumerate(nodes):
        denominator = 1
        for j, tj in enumerate(nodes):
            if i != j:
                denominator = denominator * (ti - tj) % p
        out.append(pow(denominator, -1, p))
    return out


def interpolate(nodes, values, p):
    n = len(nodes)
    matrix = [[pow(t, k, p) for k in range(n)] for t in nodes]
    answer = solve(matrix, values, n, p)
    if answer is None:
        raise LedgerError('Invalid interpolation nodes')
    return answer


def evaluate(poly, x, p):
    out = 0
    for c in reversed(poly):
        out = (out * x + c) % p
    return out


@dataclass(frozen=True)
class Problem:
    target_id: str
    columns: tuple[tuple[int, ...], ...]
    eta: tuple[int, ...]
    gamma: tuple[int, ...]
    source_order: tuple[str, ...]
    mode: str = 'recorded_eta'
    context_id: str = ''

    @property
    def dimension(self):
        return len(self.source_order)

    @property
    def slots(self):
        return len(self.columns)


def audit(problem: Problem, capability, p):
    """Return and verify a dual certificate or a normalized formal witness."""
    d, n = problem.dimension, problem.slots
    if len(problem.eta) != n or len(problem.gamma) != n or any(len(c) != d for c in problem.columns):
        raise LedgerError('Malformed target')
    U = RowSpace(capability, d, p)
    H = nullspace(U.rows, d, p)
    constraints = [[problem.eta[i] if i == j else 0 for i in range(n)] for j in range(n)]
    constraints += [[dot(h, col, p) for col in problem.columns] for h in H]
    x = solve(constraints + [list(problem.gamma)], [0] * len(constraints) + [p - 1], n, p)
    out = {'target_id': problem.target_id, 'context_id': problem.context_id,
           'mode': problem.mode, 'effective_eta': list(problem.eta),
           'source_order': list(problem.source_order), 'capability_rank': U.rank,
           'evidence_level': 'FINITE_FIELD_FORMAL', 'group_replay_verified': False}
    if x is not None:
        u = combination(x, problem.columns, d, p)
        out.update(status='FORMAL_WITNESS' if problem.mode == 'recorded_eta' else 'UNCERTIFIED',
                   x=x, target_direction=u,
                   capability_combination=solve(transpose(U.rows, d), u, U.rank, p))
    else:
        matrix = [row + [0] * n for row in U.rows]
        rhs = [0] * U.rank
        for i, col in enumerate(problem.columns):
            arow = [0] * n
            arow[i] = problem.eta[i]
            matrix.append(list(col) + arow)
            rhs.append(problem.gamma[i])
        solution = solve(matrix, rhs, d + n, p)
        if solution is None:
            raise LedgerError('Neither certificate nor witness found: internal algebra error')
        out.update(status='PROTECTED', z=solution[:d], a=solution[d:])
    verify_audit(problem, U.rows, out, p)
    out['algebraic_verification'] = True
    return out


def verify_audit(problem, capability, result, p):
    U = RowSpace(capability, problem.dimension, p)
    if result['status'] == 'PROTECTED':
        z, a = result['z'], result['a']
        if len(z) != problem.dimension or len(a) != problem.slots:
            raise LedgerError('Certificate dimensions differ')
        if any(dot(u, z, p) for u in U.rows):
            raise LedgerError('Certificate z does not annihilate capability')
        if any((dot(col, z, p) + problem.eta[i] * a[i] - problem.gamma[i]) % p for i, col in enumerate(problem.columns)):
            raise LedgerError('Certificate target equality fails')
    elif result['status'] in ('FORMAL_WITNESS', 'UNCERTIFIED'):
        x = result['x']
        if len(x) != problem.slots or any(a * b % p for a, b in zip(problem.eta, x)):
            raise LedgerError('Witness residual constraint fails')
        if dot(problem.gamma, x, p) != p - 1:
            raise LedgerError('Witness is not normalized to gamma*x=-1')
        if not U.contains(combination(x, problem.columns, problem.dimension, p)):
            raise LedgerError('Witness direction is not in capability')
    else:
        raise LedgerError('Unsupported audit result status')
    return True


class IncrementalAudit:
    """Proposition D.1 with persistent V,W and a rank-one certificate update."""
    def __init__(self, problem, capability, p):
        self.problem, self.p = problem, p
        self.U = RowSpace(capability, problem.dimension, p)
        self.result = audit(problem, self.U.rows, p)
        if self.result['status'] != 'PROTECTED':
            raise LedgerError('D.1 requires the initial capability to protect the target')
        allowed = [i for i, value in enumerate(problem.eta) if value % p == 0]
        k0_constraints = [[problem.eta[i] if i == j else 0 for i in range(problem.slots)] for j in range(problem.slots)]
        k0_constraints.append(list(problem.gamma))
        self.V = RowSpace(self.U.rows + [list(problem.columns[i]) for i in allowed], problem.dimension, p)
        self.W = RowSpace(self.U.rows + [combination(x, problem.columns, problem.dimension, p)
                                      for x in nullspace(k0_constraints, problem.slots, p)], problem.dimension, p)
        if self.V.rank - self.W.rank not in (0, 1):
            raise LedgerError('Initial V/W has dimension above one')

    def append(self, full_increment):
        """Consumes all new restored directions, not merely the new payload row."""
        # Callers may provide one-shot iterators; both passes use this snapshot.
        full_increment = [list(row) for row in full_increment]
        new_U = self.U.copy()
        for row in full_increment:
            new_U.insert(row)
        categories = []
        if self.result['status'] != 'PROTECTED':
            self.U = new_U
            self.result = audit(self.problem, new_U.rows, self.p)
            self.result['incremental_applicable'] = False
            return self.result
        z, a = self.result['z'][:], self.result['a'][:]
        for supplied in full_increment:
            row = [x % self.p for x in supplied]
            if self.W.contains(row):
                categories.append('IN_W_SAFE')
                self.U.insert(row)
                continue
            if self.V.contains(row):
                categories.append('IN_V_NOT_W_WITNESS')
                self.U = new_U
                self.result = audit(self.problem, new_U.rows, self.p)
                if self.result['status'] == 'PROTECTED':
                    raise LedgerError('D.1 and batch disagree on unsafe increment')
                self.result['incremental_categories'] = categories
                self.result['incremental_applicable'] = True
                return self.result
            categories.append('OUTSIDE_V_SAFE_CERTIFICATE_EXTENSION')
            residual = dot(z, row, self.p)
            if residual:
                delta = solve(self.V.rows + [row], [0] * self.V.rank + [-residual % self.p], self.problem.dimension, self.p)
                if delta is None:
                    raise LedgerError('Certificate extension has no solution')
                z = [(x + y) % self.p for x, y in zip(z, delta)]
            self.V.insert(row)
            self.W.insert(row)
            self.U.insert(row)
        # The extension annihilates F K, not necessarily every column F_i.
        # Refresh the residual certificate component on nonzero-eta slots.
        a = [((self.problem.gamma[i] - dot(col, z, self.p)) * pow(self.problem.eta[i], -1, self.p)) % self.p
             if self.problem.eta[i] % self.p else 0
             for i, col in enumerate(self.problem.columns)]
        self.result = {'target_id': self.problem.target_id, 'context_id': self.problem.context_id,
                       'mode': self.problem.mode, 'effective_eta': list(self.problem.eta),
                       'source_order': list(self.problem.source_order),
                       'capability_rank': self.U.rank, 'status': 'PROTECTED', 'z': z, 'a': a,
                       'evidence_level': 'FINITE_FIELD_FORMAL', 'group_replay_verified': False,
                       'incremental_categories': categories, 'incremental_applicable': True}
        verify_audit(self.problem, self.U.rows, self.result, self.p)
        self.result['algebraic_verification'] = True
        return self.result


@dataclass(frozen=True)
class Source:
    source_id: str
    kind: str
    owner: str
    slot: int | None
    generation: str
    origin: str = 'declared_generator'
    assurance: str = 'synthetic_fixture'
    sampling_reference: str = ''


@dataclass(frozen=True)
class Observation:
    observation_id: str
    kind: str
    ordinary: dict[str, int] = field(default_factory=dict)
    pads: dict[str, int] = field(default_factory=dict)
    constant: int = 0
    rhs: int | None = None
    rhs_provenance: str = ''
    observer_available: bool = True
    constant_available: bool = True
    origin: str = 'coefficient_fixture'
    plan_id: str = ''
    original_context: str = ''
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Target:
    target_id: str
    columns: tuple[dict[str, int], ...]
    nodes: tuple[int, ...]
    recorded_eta: tuple[int, ...] | None
    context_id: str
    certified_nonzero_slots: tuple[int, ...] = ()
    certification_provenance: str = ''
    source_assurance: str = 'declared_generator'


@dataclass(frozen=True)
class FrozenPlan:
    plan_id: str
    expected_observations: tuple[Observation, ...]
    contract: str = 'canonical_sources_independent_protected_pads'


class Registry:
    def __init__(self, p):
        self.p = p
        self.sources = {}
        self.aliases = {}

    def add(self, source):
        if source.source_id in self.sources or source.source_id in self.aliases:
            raise LedgerError('Immutable source ID already exists')
        if source.kind not in ('core', 'service_core', 'mask', 'pad'):
            raise LedgerError('Unsupported source kind')
        if source.kind != 'pad' and source.slot is None:
            raise LedgerError('Ordinary sources require a slot for numerical localization')
        self.sources[source.source_id] = source

    def resolve(self, name):
        canonical = self.aliases.get(name, name)
        if canonical not in self.sources:
            raise LedgerError(f'Unknown source: {name}')
        return canonical

    def alias(self, alias, source_id):
        canonical = self.resolve(source_id)
        if alias in self.sources or alias in self.aliases:
            raise LedgerError('Alias identity already exists')
        self.aliases[alias] = canonical

    def coefficients(self, mapping, kind):
        out = {}
        for name, coefficient in mapping.items():
            if not isinstance(coefficient, int):
                raise LedgerError('Finite-field coefficients must be exact integers')
            canonical = self.resolve(name)
            is_pad = self.sources[canonical].kind == 'pad'
            if is_pad != (kind == 'pad'):
                raise LedgerError('Ordinary/pad source kind mismatch')
            out[canonical] = (out.get(canonical, 0) + int(coefficient)) % self.p
        return {name: c for name, c in out.items() if c}

    def orders(self):
        ordinary = [name for name, x in self.sources.items() if x.kind != 'pad']
        pads = [name for name, x in self.sources.items() if x.kind == 'pad']
        return ordinary, pads

    def observation(self, obs):
        if obs.kind not in ('point', 'scalar'):
            raise LedgerError('Only constant-coefficient points and affine scalar observations are supported')
        if not obs.observer_available:
            raise LedgerError('Analysis-only values and private points are not observer capability')
        if not isinstance(obs.constant, int) or (obs.rhs is not None and not isinstance(obs.rhs, int)):
            raise LedgerError('Affine constants and RHS must be exact integers')
        if obs.kind == 'scalar' and not obs.constant_available:
            raise LedgerError('A hidden scalar offset must be modeled as an unknown source, not subtracted as public data')
        if obs.kind == 'scalar' and (obs.rhs is None or not obs.observer_available or not obs.rhs_provenance):
            raise LedgerError('Numerical capability requires an actual observer-available RHS and provenance')
        return Observation(obs.observation_id, obs.kind, self.coefficients(obs.ordinary, 'ordinary'),
                           self.coefficients(obs.pads, 'pad'), obs.constant % self.p,
                           None if obs.rhs is None else obs.rhs % self.p, obs.rhs_provenance,
                           obs.observer_available, obs.constant_available, obs.origin,
                           obs.plan_id, obs.original_context, tuple(obs.dependencies))


def capability(registry, observations):
    """Equation (padcap), using immutable IDs and actual affine scalar RHS.

    Points are constant-coefficient representatives. The public projection
    kernel is part of the formal source model, not implemented curve objects.
    Direct low-level calls may retain unavailable point offsets for private
    formal analysis; such output is not an observer transcript. HistoryAuditor
    rejects these descriptors at public admission and redacts visible inputs.
    """
    p = registry.p
    ordinary, pads = registry.orders()
    d, nr = len(ordinary), len(pads)
    points, scalars = [], []
    for observation in observations:
        normalized = registry.observation(observation)
        (points if normalized.kind == 'point' else scalars).append(normalized)
    P = [[x.ordinary.get(name, 0) for name in ordinary] for x in points]
    B = [[x.pads.get(name, 0) for name in pads] for x in points]
    Lw = [[x.ordinary.get(name, 0) for name in ordinary] for x in scalars]
    Lr = [[x.pads.get(name, 0) for name in pads] for x in scalars]
    ell = [(x.rhs - x.constant) % p for x in scalars]
    if solve([w + r for w, r in zip(Lw, Lr)], ell, d + nr, p) is None:
        raise LedgerError('Inconsistent actual numerical RHS: no affine source fiber')
    rows, recipes = [], []
    slots = sorted({registry.sources[name].slot for name in ordinary})
    for c in nullspace(transpose(Lr, nr), len(scalars), p):
        row = combination(c, Lw, d, p)
        for slot in slots:
            localized = [v if registry.sources[name].slot == slot else 0 for name, v in zip(ordinary, row)]
            if any(localized):
                rows.append(localized)
                recipes.append({'kind': 'FORMAL_NUMERICAL_SLOT_RESTRICTION', 'slot': slot,
                                'scalar_coefficients': {x.observation_id: v for x, v in zip(scalars, c) if v},
                                'original_affine_rhs_combination': dot(c, ell, p),
                                'native_point_representation_verified': False})
    all_pad_rows = B + Lr
    for bc in nullspace(transpose(all_pad_rows, nr), len(all_pad_rows), p):
        b, c = bc[:len(points)], bc[len(points):]
        row1 = combination(b, P, d, p)
        row2 = combination(c, Lw, d, p)
        row = [(x + y) % p for x, y in zip(row1, row2)]
        if not any(row):
            continue
        rows.append(row)
        recipes.append({'kind': 'FORMAL_PAD_CANCEL_COMBINATION',
                        'point_coefficients': {x.observation_id: v for x, v in zip(points, b) if v},
                        'scalar_coefficients': {x.observation_id: v for x, v in zip(scalars, c) if v},
                        'known_h_correction': (dot(c, ell, p) - sum(v*x.constant for v, x in zip(b, points))) % p,
                        'constant_correction_observer_available': all(x.constant_available for v, x in zip(b, points) if v),
                        'native_point_representation_verified': False})
    U = RowSpace(rows, d, p)
    combinations_of_generators = [solve(transpose(rows, d), row, len(rows), p) for row in U.rows]
    return {'source_order': ordinary, 'pad_order': pads, 'basis': U.rows, 'rank': U.rank,
            'point_observations': len(points), 'scalar_observations': len(scalars),
            'generators': rows, 'generator_recipes': recipes,
            'basis_combinations_of_generators': combinations_of_generators,
            'numerical_rows': [{'observation_id': x.observation_id, 'rhs': x.rhs,
                                'offset': x.constant, 'normalized_rhs': value,
                                'rhs_provenance': x.rhs_provenance,
                                'original_context': x.original_context,
                                'dependencies': list(x.dependencies)} for x, value in zip(scalars, ell)],
            'scope': 'Formal coefficient capability; no native group handles or KDF replay'}


def problem_for(target, registry, mode):
    ordinary, _ = registry.orders()
    columns = tuple(tuple(registry.coefficients(col, 'ordinary').get(name, 0) for name in ordinary) for col in target.columns)
    if mode == 'recorded_eta':
        if target.recorded_eta is None:
            raise LedgerError('Offline recorded_eta audit requires separately supplied private residuals')
        eta = tuple(x % registry.p for x in target.recorded_eta)
        if len(eta) != len(columns):
            raise LedgerError('Offline residual array does not match the target slots')
    elif mode == 'public_D':
        # Deliberately do not read target.recorded_eta in this branch.
        D = set(target.certified_nonzero_slots)
        if D and not target.certification_provenance:
            raise LedgerError('Public nonzero residual set requires independent certification provenance')
        if any(i < 0 or i >= len(columns) for i in D):
            raise LedgerError('Certified residual index out of range')
        eta = tuple(int(i in D) for i in range(len(columns)))
    else:
        raise LedgerError('Unknown audit mode')
    return Problem(target.target_id, columns, eta, tuple(lagrange_gamma(target.nodes, registry.p)),
                   tuple(ordinary), mode, target.context_id)


def restored_increment(old_basis, new_basis, d, p):
    old = RowSpace(old_basis, d, p)
    new = RowSpace(new_basis, d, p)
    if any(not new.contains(row) for row in old.rows):
        raise LedgerError('Visible history capability must not shrink')
    result = []
    for row in new.rows:
        if old.insert(row):
            result.append(list(row))
    return result


class HistoryAuditor:
    """Reference state semantics, with candidate preflight and append-only visibility."""
    def __init__(self, p=101):
        self.p = p
        self.registry = Registry(p)
        self.observations = {}
        self.visible_events = []
        self.decisions = []
        self.targets = {}
        self.plans = {}
        self.completed_plans = set()
        self.active_dictionary = {}
        self.unresolved_events = []

    def add_source(self, source, node=None):
        if node is not None and (source.kind != 'core' or not (0 < node < self.p) or node in self.active_dictionary.values()):
            raise LedgerError('Active dictionary nodes must be distinct nonzero protected-core nodes')
        self.registry.add(source)
        if node is not None:
            self.active_dictionary[source.source_id] = node

    def add_target(self, target):
        if not target.nodes or len(target.nodes) != len(target.columns):
            raise LedgerError('Targets must have nonempty matching slot arrays')
        lagrange_gamma(target.nodes, self.p)  # Validate the original node encoding before committing it.
        if target.target_id in self.targets:
            raise LedgerError('Immutable target ID already exists')
        normalized = Target(target.target_id, tuple(self.registry.coefficients(c, 'ordinary') for c in target.columns),
                            tuple(target.nodes), target.recorded_eta, target.context_id,
                            tuple(target.certified_nonzero_slots), target.certification_provenance, target.source_assurance)
        self.targets[target.target_id] = normalized


    def _public_trial_copy(self):
        # Do not deepcopy, iterate, serialize, or otherwise materialize hidden eta.
        trial = HistoryAuditor(self.p)
        trial.registry = copy.deepcopy(self.registry)
        trial.observations = copy.deepcopy(self.observations)
        trial.visible_events = copy.deepcopy(self.visible_events)
        trial.decisions = copy.deepcopy(self.decisions)
        trial.targets = {name: replace(target, recorded_eta=None) for name, target in self.targets.items()}
        trial.plans = copy.deepcopy(self.plans)
        trial.completed_plans = set(self.completed_plans)
        trial.active_dictionary = dict(self.active_dictionary)
        trial.unresolved_events = copy.deepcopy(self.unresolved_events)
        return trial

    @staticmethod
    def public_target_descriptor(target):
        # Explicit allowlist avoids touching or exporting the private eta field.
        return {'target_id': target.target_id, 'columns': copy.deepcopy(target.columns),
                'nodes': list(target.nodes), 'context_id': target.context_id,
                'certified_nonzero_slots': list(target.certified_nonzero_slots),
                'certification_provenance': target.certification_provenance,
                'source_assurance': target.source_assurance}

    def _all_observations(self, include_pending=False):
        observations = dict(self.observations)
        if include_pending:
            for plan in self.plans.values():
                for obs in plan.expected_observations:
                    if obs.observation_id in observations and observations[obs.observation_id] != obs:
                        raise LedgerError('Frozen plan conflicts with an original visible payload')
                    observations.setdefault(obs.observation_id, obs)
        return list(observations.values())

    def current_capability(self, include_pending=False):
        if self.unresolved_events:
            raise LedgerError('Visible but unsupported payloads remain unresolved; protection cannot be certified')
        return capability(self.registry, self._all_observations(include_pending))

    def audit_all(self, mode='public_D', include_pending=False):
        cap = self.current_capability(include_pending)
        return {name: audit(problem_for(target, self.registry, mode), cap['basis'], self.p)
                for name, target in self.targets.items()}

    def transition(self, old_cap, new_cap, mode='public_D'):
        d = len(new_cap['source_order'])
        if old_cap['source_order'] != new_cap['source_order']:
            raise LedgerError('Transition expects both restored bases in the same source order')
        increment = restored_increment(old_cap['basis'], new_cap['basis'], d, self.p)
        records = {}
        for name, target in self.targets.items():
            problem = problem_for(target, self.registry, mode)
            before = audit(problem, old_cap['basis'], self.p)
            batch = audit(problem, new_cap['basis'], self.p)
            if before['status'] == 'PROTECTED':
                incremental = IncrementalAudit(problem, old_cap['basis'], self.p).append(increment)
                if incremental['status'] != batch['status']:
                    raise LedgerError('Batch and incremental audit disagree')
                verify_audit(problem, new_cap['basis'], incremental, self.p)
                records[name] = {'batch': batch, 'incremental': incremental, 'semantic_match': True}
            else:
                records[name] = {'batch': batch, 'incremental_applicable': False,
                                 'reason': 'D.1 requires an initially protected target'}
        return {'full_restored_increment': increment, 'increment_rank': len(increment), 'targets': records}

    def _public_observation(self, supplied):
        if not supplied.constant_available:
            raise LedgerError('Public controller requires public affine offsets; model a private offset as an unknown source')
        return self.registry.observation(supplied)

    @staticmethod
    def _public_payload_descriptor(supplied):
        # Never serialize/hash a private numerical offset in the public ledger.
        public = supplied if supplied.constant_available else replace(supplied, constant=None)
        return asdict(public)

    def controlled_output(self, supplied):
        """No candidate bytes enter the visible ledger before successful preflight."""
        obs = self._public_observation(supplied)
        if obs.observation_id in self.observations:
            if self.observations[obs.observation_id] != obs:
                raise LedgerError('Conflicting reuse of original observation identity')
            decision = {'action': 'REPLAY_NO_NEW_OUTPUT', 'observation_id': obs.observation_id}
            self.decisions.append(decision)
            return decision
        trial = self._public_trial_copy()
        trial.observations[obs.observation_id] = obs
        actual_before = self.current_capability()
        actual_after = trial.current_capability()
        reserved_after = trial.current_capability(include_pending=True)
        public = {name: audit(problem_for(t, trial.registry, 'public_D'), reserved_after['basis'], self.p)
                  for name, t in trial.targets.items()}
        decision = {'action': 'COMMITTED' if all(x['status'] == 'PROTECTED' for x in public.values()) else 'REJECTED_BEFORE_VISIBILITY',
                    'observation_id': obs.observation_id, 'preflight_public_D': public,
                    'reserved_capability_rank': reserved_after['rank'],
                    'candidate_transition': self.transition(actual_before, actual_after, mode='public_D'),
                    'visible_count_before': len(self.visible_events)}
        if decision['action'] == 'COMMITTED':
            # Commit exactly the same normalized descriptor that passed preflight.
            self.observations[obs.observation_id] = obs
            self.visible_events.append({'sequence': len(self.visible_events), 'visibility': 'CONTROLLED_COMMIT',
                                        'payload_sha256': digest(asdict(obs)), 'payload': asdict(obs)})
        decision['visible_count_after'] = len(self.visible_events)
        self.decisions.append(decision)
        return decision

    def observe_visible(self, supplied, reason='externally visible or compelled disclosure'):
        """Visibility is irrevocable, even when policy or descriptor checks fail."""
        public_payload = self._public_payload_descriptor(supplied)
        event = {'sequence': len(self.visible_events), 'visibility': 'ALREADY_VISIBLE',
                 'reason': reason, 'payload_sha256': digest(public_payload), 'payload': public_payload,
                 'private_offset_redacted': not supplied.constant_available}
        self.visible_events.append(event)
        try:
            obs = self._public_observation(supplied)
            if obs.observation_id in self.observations:
                if self.observations[obs.observation_id] != obs:
                    raise LedgerError('Visible conflicting reuse of an immutable observation ID')
                return {'action': 'VISIBLE_REPLAY_RETAINED', 'observation_id': obs.observation_id}
            before = self.current_capability()
            self.observations[obs.observation_id] = obs
            after = self.current_capability()
            transition = self.transition(before, after, mode='public_D')
            public = self.audit_all('public_D')
            return {'action': 'VISIBLE_RETAINED', 'observation_id': obs.observation_id,
                    'transition': transition, 'public_D': public}
        except LedgerError as exc:
            self.unresolved_events.append({'sequence': event['sequence'], 'error': str(exc)})
            return {'action': 'VISIBLE_RETAINED_UNRESOLVED', 'error': str(exc),
                    'protection_certification_blocked': True}

    def freeze_plan(self, plan):
        if plan.plan_id in self.plans:
            raise LedgerError('Frozen plan ID already exists')
        normalized = FrozenPlan(plan.plan_id, tuple(self._public_observation(x) for x in plan.expected_observations), plan.contract)
        trial = self._public_trial_copy()
        trial.plans[normalized.plan_id] = normalized
        cap = trial.current_capability(include_pending=True)
        public = trial.audit_all('public_D', include_pending=True)
        decision = {'action': 'PLAN_FROZEN' if all(x['status'] == 'PROTECTED' for x in public.values()) else 'PLAN_REJECTED',
                    'plan_id': plan.plan_id, 'complete_reserved_basis': cap['basis'],
                    'complete_reserved_rank': cap['rank'], 'preflight_public_D': public,
                    'plan_sha256': digest(asdict(normalized))}
        if decision['action'] == 'PLAN_FROZEN':
            self.plans[plan.plan_id] = normalized
        self.decisions.append(decision)
        return decision

    def complete_plan(self, plan_id):
        plan = self.plans[plan_id]
        if any(self.observations.get(x.observation_id) != x for x in plan.expected_observations):
            raise LedgerError('Plan is not fully visible under its original payload identities')
        self.completed_plans.add(plan_id)
        # The plan remains archived; its points are already visible and retained.
        return {'action': 'PLAN_COMPLETED_RETAINED', 'plan_id': plan_id}

    def _pure_core_basis(self, cap):
        core_ids = list(self.active_dictionary)
        order = cap['source_order']
        keep = [order.index(x) for x in core_ids]
        outside = [i for i in range(len(order)) if i not in keep]
        constraints = [[row[i] for row in cap['basis']] for i in outside]
        rows = []
        for c in nullspace(constraints, cap['rank'], self.p):
            full = combination(c, cap['basis'], len(order), self.p)
            rows.append([full[i] for i in keep])
        return RowSpace(rows, len(keep), self.p).rows

    def check_enrollment(self, source_id, node, use_pending=True):
        if source_id in self.registry.sources or source_id in self.registry.aliases or not (0 < node < self.p) or node in self.active_dictionary.values():
            raise LedgerError('Enrollment requires an unused source ID and node')
        cap = self.current_capability(include_pending=use_pending)
        ids, nodes = list(self.active_dictionary), list(self.active_dictionary.values())
        if len(ids) > 8:
            raise LedgerError('Reference universal-family check is limited to at most 8 current cores')
        pure = self._pure_core_basis(cap)
        # Check the theorem's old-family premise explicitly, for every subset.
        for size in range(1, len(ids) + 1):
            for J in combinations(range(len(ids)), size):
                columns = tuple(tuple(int(i == j) for i in range(len(ids))) for j in J)
                problem = Problem('old_universal_subset', columns, (0,) * len(J),
                                  tuple(lagrange_gamma([nodes[j] for j in J], self.p)), tuple(ids))
                if audit(problem, pure, self.p)['status'] != 'PROTECTED':
                    return {'action': 'ENROLLMENT_UNCERTIFIED_OLD_FAMILY', 'use_pending': use_pending}
        evaluations = []
        for row in pure:
            poly = interpolate(nodes, row, self.p)
            evaluations.append({'old_direction': row, 'interpolant': poly, 'new_node_value': evaluate(poly, node, self.p)})
        safe = all(x['new_node_value'] == 0 for x in evaluations)
        return {'action': 'ENROLLMENT_CERTIFIED' if safe else 'ENROLLMENT_REJECTED_PENDING_OR_RETAINED_DIRECTION',
                'source_id': source_id, 'node': node, 'use_pending': use_pending,
                'pure_core_reserved_rank': len(pure), 'basis_evaluations': evaluations,
                'original_setup_node_membership_checked': False,
                'scope': 'Common-zero condition for universal canonical empty-policy targets. Caller must verify membership in the original published setup-node set; no group replay'}

    def snapshot(self):
        out = {'sources': [asdict(x) for x in self.registry.sources.values()], 'aliases': dict(self.registry.aliases),
               'active_dictionary': dict(self.active_dictionary),
               'original_targets': [self.public_target_descriptor(x) for x in self.targets.values()],
               'visible_events': copy.deepcopy(self.visible_events), 'decisions': copy.deepcopy(self.decisions),
               'frozen_plans': [asdict(x) for x in self.plans.values()],
               'completed_plans': sorted(self.completed_plans), 'unresolved_events': copy.deepcopy(self.unresolved_events)}
        if not self.unresolved_events:
            out['actual_capability'] = self.current_capability()
            out['reserved_capability'] = self.current_capability(True)
            out['public_audit'] = self.audit_all('public_D')
        return out
