"""Public-coefficient, serial CHARE reference admission controller.

Scope: canonical cores; ordinary masks granted for message capability; connected
incidence-pad plans; pad-only linear openings; proved polynomial envelopes.
This module does NOT implement a group, KDF, RO/delivery restoration, signatures,
or a proof that a signed record was honestly generated. binding_verifier is an
explicit adapter to the already trusted/authenticated generation interface.
All secret-dependent emission is behind a zero-argument callback. The callback
must implement its declared row. Its public payload remains in the backend and
is identified here by an opaque handle; no candidate RHS is an API argument.
"""
from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Callable

try:
    from .field import (basis, in_span, interpolate, is_prime64, joint_capability,
                        peval, pmul, target_witness, trim, universal_witness)
except ImportError:
    from field import (basis, in_span, interpolate, is_prime64, joint_capability,
                       peval, pmul, target_witness, trim, universal_witness)


def public_encoding(value):
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(public_encoding(value)).hexdigest()


def typed_key(kind, *parts):
    """Exact injective typed serialization; no hash-collision premise for row identity."""
    return "typed:" + public_encoding([kind, *parts]).decode("ascii")


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    kind: str
    owner_id: str
    root_id: str
    node: int
    generation_id: str
    fact_id: str | None
    profile: str
    origin_ref: str


@dataclass(frozen=True)
class Envelope:
    dimension: int
    reserved_nodes: tuple[int, ...] = ()

    def polynomials(self, p):
        factor = (1,)
        for x in self.reserved_nodes:
            factor = pmul(factor, (-x, 1), p)
        return tuple((0,) * d + factor for d in range(self.dimension))

    def rows(self, nodes, p):
        return tuple(tuple(peval(f, x, p) for x in nodes)
                     for f in self.polynomials(p))


@dataclass(frozen=True)
class PadEdge:
    pad_id: str
    tail: str
    head: str
    delivery_ref: str


@dataclass(frozen=True)
class MaskPair:
    core_id: str
    first_mask_id: str
    second_mask_id: str


@dataclass(frozen=True)
class Plan:
    plan_id: str
    invocation_id: str
    direction_id: str
    dictionary_epoch: int
    participants: tuple[str, ...]
    polynomial: tuple[int, ...]
    edges: tuple[PadEdge, ...]
    mask_pairs: tuple[MaskPair, ...] = ()
    generation_profile: str = "canonical_incidence_service_v1"


@dataclass(frozen=True)
class CanonicalTarget:
    target_id: str
    source_ids: tuple[str, ...]
    ciphertext_ref: str
    context_ref: str
    profile: str = "canonical_empty_policy"


@dataclass(frozen=True)
class Decision:
    status: str
    reason: str
    revision: int
    private_callback_called: bool = False
    evidence: dict = field(default_factory=dict)

    @property
    def accepted(self):
        return self.status in ("ADMITTED", "RECORDED", "REPLAY")

    def to_dict(self):
        return asdict(self)


@dataclass
class _PlanState:
    plan: Plan
    digest: str
    phase: str = "FROZEN"
    emitted: set = field(default_factory=set)


class Controller:
    """Single-threaded reference object. Mutating callback reentry is rejected.

    The verifier sees only a public descriptor dict and its public receipt. An
    application must supply an actual authenticated generation adapter. Tests
    use an explicit trusted-manifest fixture, not a cryptographic signature.
    Primes below 2**64 are checked deterministically. Larger moduli require an
    explicit prime_is_prevalidated=True declaration from the existing parameter
    profile; no new curve-security or parameter-generation claim is made.
    """
    def __init__(self, p, setup_nodes, cores, envelope, binding_verifier,
                 prime_is_prevalidated=False):
        if type(p) is not int or p < 3 or p % 2 == 0:
            raise ValueError("an odd prime field is required")
        if p < 1 << 64:
            if not is_prime64(p):
                raise ValueError("composite field modulus")
        elif prime_is_prevalidated is not True:
            raise ValueError("large moduli require prime_is_prevalidated=True from the original profile")
        self.p = p
        self.setup_nodes = tuple(setup_nodes)
        if (len(self.setup_nodes) < 2 or p <= len(self.setup_nodes) + 1 or
                len(set(self.setup_nodes)) != len(self.setup_nodes) or
                any(type(t) is not int or not 0 < t < p for t in self.setup_nodes)):
            raise ValueError("invalid setup node dictionary")
        if not callable(binding_verifier):
            raise ValueError("an explicit authenticated-generation adapter is required")
        self._verify = binding_verifier
        self._sources, self._aliases = {}, {}
        self._core_ids = []
        self._plans, self._targets = {}, {}
        self._pad_ids = []
        self._relation_rows = {}
        self._observed_rows = {}
        self._payloads = {}
        self._target_handles = {}
        self._contract_violation = False
        self._callback_active = False
        self._ingest_queue = []
        self.callback_count = 0
        self.revision = 0
        self.dictionary_epoch = 0
        self.trace = []
        for source, receipt in cores:
            why = self._validate_source(source, receipt, initial=True)
            if why:
                raise ValueError(why)
            self._sources[source.source_id] = source
            self._core_ids.append(source.source_id)
        if len(self._core_ids) < 2:
            raise ValueError("the canonical service starts with at least two cores")
        self._check_envelope(envelope, self.nodes)
        self.envelope = envelope
        self._event("INITIALIZED", core_count=len(self._core_ids),
                    assurance="authenticated_generation_premise",
                    capability_scope="ordinary_masks_granted; coefficient_only")

    @property
    def nodes(self):
        return tuple(self._sources[x].node for x in self._core_ids)

    def _event(self, event, **data):
        self.trace.append({"seq": len(self.trace), "event": event,
                           "revision": self.revision, **data})

    def _reject(self, operation, reason, status="UNCERTIFIED", evidence=None):
        evidence = evidence or {}
        self._event("REJECT", operation=operation, reason=reason, status=status,
                    callback_count=self.callback_count, evidence=evidence)
        return Decision(status, reason, self.revision, False, evidence)

    def _begin(self, operation, expected_revision):
        if self._callback_active:
            return self._reject(operation, "MUTATING_CALLBACK_REENTRY")
        if type(expected_revision) is not int or expected_revision != self.revision:
            return self._reject(operation, "STALE_REVISION", "UNCERTIFIED",
                                {"expected": expected_revision, "actual": self.revision})
        return None

    def _commit(self, operation, **data):
        self.revision += 1
        self._event("COMMIT", operation=operation, **data)

    def _emit(self, operation, emitter, payload_key, on_success=None, on_failure=None):
        # The caller has ALREADY committed every possibly exposed coefficient row.
        self._callback_active = True
        self.callback_count += 1
        self._event("PRIVATE_CALLBACK_BEGIN", operation=operation,
                    payload_key=payload_key, callback_count=self.callback_count)
        error_type, public_handle = None, None
        try:
            public_handle = emitter()
            if not isinstance(public_handle, str) or not public_handle:
                raise TypeError("emitter must return a nonempty public handle")
            self._payloads[payload_key] = public_handle
            if on_success:
                on_success(public_handle)
        except Exception as exc:
            # Do not log exception text: it could contain a private backend value.
            error_type = type(exc).__name__
            self._payloads[payload_key] = "possibly-visible:" + payload_key
            if on_failure:
                on_failure()
            self._event("PRIVATE_CALLBACK_UNCERTAIN", operation=operation,
                        error_type=error_type, coefficient_rows_retained=True)
        finally:
            self._callback_active = False
            self._drain_observations()
        if error_type:
            return Decision("EMISSION_UNCERTAIN", "CALLBACK_MAY_HAVE_EMITTED",
                            self.revision, True,
                            {"retained": payload_key, "rollback": False})
        audit = self._guard(self._capability(True))
        self._event("PRIVATE_CALLBACK_END", operation=operation,
                    public_handle=public_handle, post_callback_audit=audit)
        return Decision("ADMITTED", "PUBLIC_GUARD_COMMITTED_BEFORE_CALLBACK",
                        self.revision, True,
                        {"public_handle": public_handle,
                         "post_callback_audit": audit or {"status": "PROTECTED"}})

    def _drain_observations(self):
        while self._ingest_queue:
            relation_id, coefficients, handle, observed_revision = self._ingest_queue.pop(0)
            self.observe_pad_opening(relation_id, coefficients, handle, observed_revision)

    def _resolve(self, source_id):
        return self._aliases.get(source_id, source_id)

    def _validate_source(self, source, receipt, initial=False):
        if not isinstance(source, SourceRecord):
            return "SOURCE_DESCRIPTOR_TYPE"
        if any(not isinstance(v, str) or not v for v in
               (source.source_id, source.owner_id, source.root_id,
                source.generation_id, source.origin_ref)):
            return "SOURCE_BINDING_MISSING"
        if source.source_id in self._sources or source.source_id in self._aliases:
            return "PHYSICAL_SOURCE_ID_ALREADY_BOUND"
        if type(source.node) is not int or source.node not in self.setup_nodes:
            return "SOURCE_NODE_OUTSIDE_SETUP"
        if source.kind == "core":
            if source.profile != "canonical_core_v1" or source.fact_id is not None:
                return "CANONICAL_CORE_PROFILE_REQUIRED"
            if any(s.kind == "core" and (s.node == source.node or s.root_id == source.root_id)
                   for s in self._sources.values()):
                return "CORE_REPLACEMENT_OR_SLOT_REBINDING"
        elif source.kind == "mask":
            if (initial or source.profile != "canonical_decision_v1" or
                    not isinstance(source.fact_id, str) or not source.fact_id):
                return "CANONICAL_MASK_PROFILE_REQUIRED"
            if not any(s.kind == "core" and (s.node, s.root_id, s.owner_id) ==
                       (source.node, source.root_id, source.owner_id)
                       for s in self._sources.values()):
                return "MASK_ROOT_OWNER_BINDING_MISSING"
        else:
            return "UNSUPPORTED_SOURCE_KIND"
        try:
            valid = self._verify(asdict(source), receipt)
        except Exception:
            valid = False
        return None if valid is True else "AUTHENTICATED_GENERATION_BINDING_FAILED"

    def _check_envelope(self, envelope, nodes):
        if not isinstance(envelope, Envelope) or type(envelope.dimension) is not int:
            raise ValueError("invalid envelope")
        future = envelope.reserved_nodes
        if (type(future) is not tuple or len(set(future)) != len(future) or
                any(type(t) is not int or t not in self.setup_nodes or t in nodes for t in future) or
                envelope.dimension < 0 or
                (envelope.dimension > 0 and 2 * envelope.dimension + len(future) > len(nodes))):
            raise ValueError("positive envelope dimension must satisfy 2*k+b<=r with unused reserved nodes")

    def install_source(self, source, receipt, expected_revision):
        op = "install_source"
        if fail := self._begin(op, expected_revision):
            return fail
        if not isinstance(source, SourceRecord) or source.kind != "mask":
            return self._reject(op, "USE_ENROLL_CORE_FOR_NEW_CORES")
        if why := self._validate_source(source, receipt):
            return self._reject(op, why)
        self._sources[source.source_id] = source
        self._commit(op, source_id=source.source_id)
        return Decision("ADMITTED", "IMMUTABLE_SOURCE_BINDING_INSTALLED", self.revision)

    def register_alias(self, alias, original_source_id, receipt, expected_revision):
        op = "register_alias"
        if fail := self._begin(op, expected_revision):
            return fail
        physical = self._resolve(original_source_id)
        payload = {"operation": "alias", "alias": alias, "physical_source_id": physical}
        if (not isinstance(alias, str) or not alias or alias in self._sources or
                alias in self._aliases or physical not in self._sources):
            return self._reject(op, "ALIAS_REBINDING_OR_UNKNOWN_SOURCE")
        try:
            valid = self._verify(payload, receipt)
        except Exception:
            valid = False
        if valid is not True:
            return self._reject(op, "ALIAS_AUTHENTICATION_FAILED")
        self._aliases[alias] = physical
        self._commit(op, alias=alias, physical_source_id=physical)
        return Decision("ADMITTED", "ALIAS_REUSES_PHYSICAL_COORDINATE", self.revision)

    def _plan_rows(self, plan):
        rows = {}
        for physical in plan.participants:
            core = {physical: peval(plan.polynomial, self._sources[physical].node, self.p)}
            pads = {}
            for edge in plan.edges:
                if edge.tail == physical:
                    pads[edge.pad_id] = 1
                elif edge.head == physical:
                    pads[edge.pad_id] = -1 % self.p
            rows[typed_key("contribution", plan.plan_id, physical)] = (core, pads)
        return rows

    def _rows(self, potential, extra_plan=None):
        rows = dict(self._observed_rows)
        if potential:
            for state in self._plans.values():
                rows.update(self._plan_rows(state.plan))
            if extra_plan is not None:
                rows.update(self._plan_rows(extra_plan))
        return rows

    def _capability(self, potential=True, extra_plan=None, extra_relation=None):
        rows = self._rows(potential, extra_plan)
        pad_ids = list(self._pad_ids)
        if extra_plan:
            pad_ids.extend(e.pad_id for e in extra_plan.edges)
        a = [tuple(core.get(i, 0) % self.p for i in self._core_ids)
             for core, pads in rows.values()]
        b = [tuple(pads.get(i, 0) % self.p for i in pad_ids)
             for core, pads in rows.values()]
        relations = list(self._relation_rows.values())
        if extra_relation is not None:
            relations.append(extra_relation)
        l = [tuple(row.get(i, 0) % self.p for i in pad_ids) for row in relations]
        return joint_capability(a, b, l, self.p, len(self._core_ids), len(pad_ids))

    def capability(self, potential=False):
        """Public coefficient result only; actual values and group handles stay separate."""
        return self._capability(potential=potential)

    def _witness_for_targets(self, cap):
        for target in self._targets.values():
            inds = tuple(self._core_ids.index(x) for x in target.source_ids)
            if w := target_witness(cap, self.nodes, inds, self.p):
                w["original_target_id"] = target.target_id
                return w
        return None

    def _guard(self, cap, envelope=None, nodes=None):
        if self._contract_violation:
            return {"status": "UNCERTIFIED", "reason": "UNMODELED_VISIBLE_PAYLOAD_RETAINED"}
        nodes = self.nodes if nodes is None else tuple(nodes)
        envelope = self.envelope if envelope is None else envelope
        allowed = envelope.rows(nodes, self.p)
        if all(in_span(row, allowed, self.p) for row in cap):
            return None
        witness = self._witness_for_targets(cap) if nodes == self.nodes else None
        witness = witness or universal_witness(cap, nodes, self.p)
        if witness:
            witness["scope"] = "mask_granted_potential_completion_space"
            witness["native_recovery_verified"] = False
            return {"status": "FORMAL_FAILURE", "reason": "CANONICAL_TARGET_WITNESS",
                    "witness": witness,
                    "completion_caveat": "Aborted/uncertain plans are conservative possible-completion reservations."}
        return {"status": "UNCERTIFIED", "reason": "OUTSIDE_APPROVED_POLYNOMIAL_ENVELOPE",
                "mathematical_break_claimed": False}

    def _reject_guard(self, op, evidence):
        return self._reject(op, evidence["reason"], evidence["status"], evidence)

    def freeze_plan(self, plan, expected_revision):
        op = "freeze_plan"
        if fail := self._begin(op, expected_revision):
            return fail
        if not isinstance(plan, Plan):
            return self._reject(op, "PLAN_DESCRIPTOR_TYPE")
        if plan.dictionary_epoch != self.dictionary_epoch:
            return self._reject(op, "STALE_DICTIONARY_EPOCH")
        if (not all(isinstance(x, str) and x for x in
                    (plan.plan_id, plan.invocation_id, plan.direction_id)) or
                plan.plan_id in self._plans or
                any((s.plan.invocation_id, s.plan.direction_id) ==
                    (plan.invocation_id, plan.direction_id) for s in self._plans.values())):
            return self._reject(op, "PLAN_ID_ALREADY_FROZEN_OR_INVALID")
        if plan.generation_profile != "canonical_incidence_service_v1":
            return self._reject(op, "UNSUPPORTED_GENERATION_PROFILE")
        # Frozen dataclasses must not contain mutable list/dict aliases.
        if any(type(v) is not tuple for v in
               (plan.participants, plan.polynomial, plan.edges, plan.mask_pairs)):
            return self._reject(op, "IMMUTABLE_TUPLE_FIELDS_REQUIRED")
        if any(not isinstance(x, str) or not x for x in plan.participants):
            return self._reject(op, "PARTICIPANT_ID_TYPE")
        parts = tuple(self._resolve(x) for x in plan.participants)
        if (not parts or len(set(parts)) != len(parts) or
                any(x not in self._core_ids for x in parts)):
            return self._reject(op, "PARTICIPANT_BINDING_MISSING_OR_DUPLICATE")
        if any(type(c) is not int for c in plan.polynomial):
            return self._reject(op, "PUBLIC_FIELD_COEFFICIENT_REQUIRED")
        f = trim(plan.polynomial, self.p)
        if not f or len(f) > len(self.nodes):
            return self._reject(op, "NONZERO_CANONICAL_INTERPOLANT_REQUIRED")
        edge_ids, edges, adjacency = set(), [], {i: set() for i in parts}
        for edge in plan.edges:
            if (not isinstance(edge, PadEdge) or
                    any(not isinstance(x, str) or not x for x in
                        (edge.pad_id, edge.tail, edge.head, edge.delivery_ref))):
                return self._reject(op, "PAD_EDGE_TYPE")
            tail, head = self._resolve(edge.tail), self._resolve(edge.head)
            if (not edge.pad_id or not edge.delivery_ref or edge.pad_id in edge_ids or
                    edge.pad_id in self._pad_ids or tail == head or
                    tail not in adjacency or head not in adjacency):
                return self._reject(op, "PAD_ID_REUSE_OR_EDGE_BINDING_ERROR")
            edge_ids.add(edge.pad_id)
            edges.append(PadEdge(edge.pad_id, tail, head, edge.delivery_ref))
            adjacency[tail].add(head)
            adjacency[head].add(tail)
        reached, todo = {parts[0]}, [parts[0]]
        while todo:
            for x in adjacency[todo.pop()] - reached:
                reached.add(x)
                todo.append(x)
        if len(reached) != len(parts):
            return self._reject(op, "CONNECTED_GRAPH_REQUIRED")
        pairs, seen = [], set()
        for pair in plan.mask_pairs:
            if (not isinstance(pair, MaskPair) or
                    any(not isinstance(x, str) or not x for x in
                        (pair.core_id, pair.first_mask_id, pair.second_mask_id))):
                return self._reject(op, "MASK_PAIR_TYPE")
            core = self._resolve(pair.core_id)
            a, b = self._resolve(pair.first_mask_id), self._resolve(pair.second_mask_id)
            if core in seen or core not in parts or a == b or a not in self._sources or b not in self._sources:
                return self._reject(op, "MASK_GENERATION_BINDING_ERROR")
            ca, cb, owner = self._sources[a], self._sources[b], self._sources[core]
            if (ca.kind != "mask" or cb.kind != "mask" or
                    ca.generation_id == cb.generation_id or
                    (ca.root_id, ca.node, ca.owner_id) != (owner.root_id, owner.node, owner.owner_id) or
                    (cb.root_id, cb.node, cb.owner_id) != (owner.root_id, owner.node, owner.owner_id)):
                return self._reject(op, "MASK_ROOT_GENERATION_BINDING_ERROR")
            if ca.fact_id != cb.fact_id:
                return self._reject(op, "DISTINCT_IMMUTABLE_FACT_IDENTITIES")
            seen.add(core)
            pairs.append(MaskPair(core, a, b))
        if pairs and seen != set(parts):
            return self._reject(op, "ALL_MASK_PAIRS_OR_CORE_ONLY_REQUIRED")
        normalized = Plan(plan.plan_id, plan.invocation_id, plan.direction_id,
                          plan.dictionary_epoch, parts, f, tuple(edges), tuple(pairs),
                          plan.generation_profile)
        full = tuple(peval(f, self._sources[i].node, self.p) if i in parts else 0
                     for i in self._core_ids)
        if any(peval(f, self._sources[i].node, self.p) for i in self._core_ids if i not in parts):
            return self._reject(op, "POLYNOMIAL_NONZERO_AT_ABSENT_PARTICIPANT")
        if not in_span(full, self.envelope.rows(self.nodes, self.p), self.p):
            return self._reject(op, "DIRECTION_OUTSIDE_APPROVED_ENVELOPE",
                                evidence={"mathematical_break_claimed": False})
        cap = self._capability(True, extra_plan=normalized)
        if failed := self._guard(cap):
            return self._reject_guard(op, failed)
        self._event("PUBLIC_GUARD_PASS", operation=op, potential_rank=len(cap))
        self._plans[normalized.plan_id] = _PlanState(normalized, digest(normalized))
        self._pad_ids.extend(edge.pad_id for edge in normalized.edges)
        self._commit(op, plan_id=normalized.plan_id, plan_digest=digest(normalized),
                     reservation="all_frozen_contribution_rows")
        return Decision("ADMITTED", "FROZEN_BEFORE_PRIVATE_INSTALLATION", self.revision,
                        evidence={"plan_digest": digest(normalized), "potential_rank": len(cap)})

    def install_pads(self, plan_id, expected_revision, emitter):
        op = "install_pads"
        if fail := self._begin(op, expected_revision):
            return fail
        state = self._plans.get(plan_id)
        if state is None or state.phase != "FROZEN" or not callable(emitter):
            return self._reject(op, "FROZEN_PLAN_AND_CALLBACK_REQUIRED")
        if failed := self._guard(self._capability(True)):
            return self._reject_guard(op, failed)
        self._event("PUBLIC_GUARD_PASS", operation=op, plan_id=plan_id)
        state.phase = "INSTALLING"
        self._commit(op, plan_id=plan_id)
        return self._emit(op, emitter, typed_key("installation", plan_id),
                          lambda h: setattr(state, "phase", "READY"),
                          lambda: setattr(state, "phase", "INSTALL_UNCERTAIN"))

    def emit_contribution(self, plan_id, source_id, expected_revision, emitter):
        op = "emit_contribution"
        if fail := self._begin(op, expected_revision):
            return fail
        if not isinstance(plan_id, str) or not isinstance(source_id, str):
            return self._reject(op, "CONTRIBUTION_ID_TYPE")
        state, source_id = self._plans.get(plan_id), self._resolve(source_id)
        if state is None or source_id not in state.plan.participants or not callable(emitter):
            return self._reject(op, "UNKNOWN_CONTRIBUTION_BINDING")
        row_id = typed_key("contribution", plan_id, source_id)
        if source_id in state.emitted:
            return Decision("REPLAY", "ORIGINAL_ROW_REUSED", self.revision,
                            evidence={"public_handle": self._payloads.get(row_id)})
        if state.phase not in ("READY", "EMITTING"):
            return self._reject(op, "PLAN_NOT_READY_OR_ABORTED")
        if failed := self._guard(self._capability(True)):
            return self._reject_guard(op, failed)
        self._event("PUBLIC_GUARD_PASS", operation=op, row_id=row_id, plan_id=plan_id, source_id=source_id)
        self._observed_rows[row_id] = self._plan_rows(state.plan)[row_id]
        state.emitted.add(source_id)
        state.phase = "EMITTING"
        self._commit(op, row_id=row_id, plan_id=plan_id, source_id=source_id, possibly_visible_row_retained=True)
        def success(handle):
            if len(state.emitted) == len(state.plan.participants):
                state.phase = "COMPLETE"
        return self._emit(op, emitter, row_id, success,
                          lambda: setattr(state, "phase", "EMISSION_UNCERTAIN"))

    def abort_plan(self, plan_id, expected_revision):
        op = "abort_plan"
        if fail := self._begin(op, expected_revision):
            return fail
        state = self._plans.get(plan_id)
        if state is None or state.phase == "COMPLETE":
            return self._reject(op, "UNKNOWN_OR_ALREADY_COMPLETE_PLAN")
        state.phase = "ABORTED_RETAINED"
        self._commit(op, plan_id=plan_id, reservation_retained=True,
                     visible_rows_retained=len(state.emitted))
        return Decision("ADMITTED", "ABORT_RETAINS_ALL_POSSIBLE_ROWS", self.revision)

    def _relation(self, relation_id, coefficients):
        if not isinstance(relation_id, str) or not relation_id or relation_id in self._relation_rows:
            return None, "PAD_RELATION_ID_ALREADY_USED_OR_MISSING"
        if not isinstance(coefficients, dict) or not coefficients:
            return None, "PAD_ONLY_PUBLIC_COEFFICIENT_MAP_REQUIRED"
        if any(not isinstance(k, str) or k not in self._pad_ids or type(v) is not int
               for k, v in coefficients.items()):
            return None, "PAD_ID_UNKNOWN_OR_COEFFICIENT_INVALID"
        row = {k: v % self.p for k, v in coefficients.items() if v % self.p}
        if not row:
            return None, "NONZERO_PAD_RELATION_REQUIRED"
        return row, None

    def request_pad_opening(self, relation_id, coefficients, expected_revision, emitter):
        op = "request_pad_opening"
        if fail := self._begin(op, expected_revision):
            return fail
        row, why = self._relation(relation_id, coefficients)
        if why or not callable(emitter):
            return self._reject(op, why or "EMITTER_REQUIRED")
        future = self._capability(True, extra_relation=row)
        if failed := self._guard(future):
            failed["visible_rank_before"] = len(self._capability(False))
            failed["potential_rank_after_proposal"] = len(future)
            return self._reject_guard(op, failed)
        self._event("PUBLIC_GUARD_PASS", operation=op, relation_id=relation_id,
                    potential_rank_after_proposal=len(future))
        self._relation_rows[relation_id] = row
        self._commit(op, relation_id=relation_id, opening_committed_before_callback=True)
        return self._emit(op, emitter, typed_key("pad-opening", relation_id))

    def observe_pad_opening(self, relation_id, coefficients, payload_handle, expected_revision):
        """Uncontrolled ALREADY-VISIBLE observation: stale revisions never erase it.

        During a private callback it enters an append-only ingest queue. The
        serial dispatcher drains that queue as soon as the callback returns.
        This is an in-memory reference queue, not a crash-persistent service.
        """
        op = "observe_pad_opening"
        if self._callback_active:
            copied = dict(coefficients) if isinstance(coefficients, dict) else coefficients
            self._ingest_queue.append((relation_id, copied, payload_handle, expected_revision))
            self._event("VISIBLE_OBSERVATION_QUEUED", operation=op,
                        relation_id=relation_id, observed_revision=expected_revision)
            return Decision("RECORDED", "VISIBLE_OBSERVATION_QUEUED_FOR_SERIAL_DRAIN",
                            self.revision)
        if expected_revision != self.revision:
            self._event("STALE_VISIBLE_OBSERVATION_RETAINED", operation=op,
                        observed_revision=expected_revision, actual_revision=self.revision)
        valid_row_shape = (isinstance(coefficients, dict) and bool(coefficients) and
                           all(isinstance(k, str) and k in self._pad_ids and type(v) is int
                               for k, v in coefficients.items()))
        if (isinstance(relation_id, str) and relation_id in self._relation_rows and valid_row_shape
                and isinstance(payload_handle, str) and bool(payload_handle)):
            normalized = {k: v % self.p for k, v in coefficients.items() if v % self.p}
            if normalized == self._relation_rows[relation_id]:
                self._event("VISIBLE_RELATION_REPLAY_RETAINED", relation_id=relation_id,
                            public_handle=payload_handle)
                return Decision("REPLAY", "ORIGINAL_PAD_RELATION_REUSED", self.revision)
        row, why = self._relation(relation_id, coefficients)
        if why or not isinstance(payload_handle, str) or not payload_handle:
            self._contract_violation = True
            self._event("UNMODELED_VISIBLE_PAYLOAD", operation=op,
                        public_handle=payload_handle if isinstance(payload_handle, str) else "untyped",
                        relation_id=relation_id, public_descriptor=coefficients)
            self._commit(op, coefficient_language_unavailable=True)
            return Decision("UNCERTIFIED", why or "PUBLIC_HANDLE_REQUIRED", self.revision)
        self._relation_rows[relation_id] = row
        self._payloads[typed_key("pad-opening", relation_id)] = payload_handle
        self._commit(op, relation_id=relation_id, already_visible=True)
        outcome = self._guard(self._capability(True))
        self._event("EXPOSURE_AUDIT", outcome=outcome or {"status": "PROTECTED"})
        return Decision("RECORDED", "UNCONTROLLED_EXPOSURE_RETAINED", self.revision,
                        evidence={"audit": outcome or {"status": "PROTECTED"}})

    def admit_target(self, target, expected_revision, emitter):
        op = "admit_target"
        if fail := self._begin(op, expected_revision):
            return fail
        if (not isinstance(target, CanonicalTarget) or
                any(not isinstance(x, str) or not x for x in
                    (target.target_id, target.ciphertext_ref, target.context_ref)) or
                target.target_id in self._targets or type(target.source_ids) is not tuple or
                any(not isinstance(x, str) or not x for x in target.source_ids) or
                target.profile != "canonical_empty_policy" or not callable(emitter)):
            return self._reject(op, "ORIGINAL_CANONICAL_TARGET_BINDING_REQUIRED")
        ids = tuple(self._resolve(x) for x in target.source_ids)
        if not ids or len(set(ids)) != len(ids) or any(x not in self._core_ids for x in ids):
            return self._reject(op, "TARGET_SOURCE_BINDING_INVALID")
        cap = self._capability(True)
        inds = tuple(self._core_ids.index(x) for x in ids)
        if witness := target_witness(cap, self.nodes, inds, self.p):
            witness["scope"] = "current_plus_frozen_possible_contributions"
            return self._reject(op, "NEW_TARGET_UNSAFE_UNDER_PENDING_COMPLETION", "FORMAL_FAILURE",
                                {"witness": witness, "native_recovery_verified": False})
        if failed := self._guard(cap):
            return self._reject_guard(op, failed)
        normalized = CanonicalTarget(target.target_id, ids, target.ciphertext_ref,
                                     target.context_ref, target.profile)
        self._event("PUBLIC_GUARD_PASS", operation=op, target_id=target.target_id)
        self._targets[target.target_id] = normalized
        self._commit(op, target_id=target.target_id, original_source_ids=list(ids))
        return self._emit(op, emitter, typed_key("target", target.target_id),
                          lambda h: self._target_handles.__setitem__(target.target_id, h))

    def enroll_core(self, source, receipt, next_envelope, expected_revision, emitter):
        op = "enroll_core"
        if fail := self._begin(op, expected_revision):
            return fail
        if not isinstance(source, SourceRecord) or source.kind != "core" or not callable(emitter):
            return self._reject(op, "NEW_CANONICAL_CORE_AND_CALLBACK_REQUIRED")
        if why := self._validate_source(source, receipt):
            return self._reject(op, why)
        new_nodes = self.nodes + (source.node,)
        try:
            self._check_envelope(next_envelope, new_nodes)
        except (ValueError, TypeError):
            return self._reject(op, "INVALID_NEXT_ENVELOPE")
        expected_reserved = set(self.envelope.reserved_nodes) - {source.node}
        if set(next_envelope.reserved_nodes) != expected_reserved:
            return self._reject(op, "REMAINING_RESERVED_NODE_PROMISE_CHANGED")
        cap = self._capability(True)
        for row in cap:
            f = interpolate(self.nodes, row, self.p)
            value = peval(f, source.node, self.p)
            if value:
                witness = target_witness(tuple(r + (0,) for r in cap), new_nodes,
                                         tuple(range(len(new_nodes))), self.p)
                return self._reject(op, "PENDING_COMMON_ZERO_CONDITION_FAILED", "FORMAL_FAILURE",
                                    {"polynomial": list(f), "new_node": source.node,
                                     "value_at_new_node": value, "witness": witness,
                                     "scope": "universal_canonical_enlarged_family",
                                     "native_recovery_verified": False})
        enlarged = tuple(row + (0,) for row in cap)
        if failed := self._guard(enlarged, next_envelope, new_nodes):
            return self._reject_guard(op, failed)
        self._event("PUBLIC_GUARD_PASS", operation=op, new_source_id=source.source_id,
                    old_source_columns_zero_extended=True)
        self._sources[source.source_id] = source
        self._core_ids.append(source.source_id)
        self.envelope = next_envelope
        self.dictionary_epoch += 1
        self._commit(op, new_source_id=source.source_id, dictionary_epoch=self.dictionary_epoch)
        return self._emit(op, emitter, typed_key("core-enrollment", source.source_id))

    def snapshot(self):
        return {"revision": self.revision, "dictionary_epoch": self.dictionary_epoch,
                "core_ids": list(self._core_ids), "nodes": list(self.nodes),
                "envelope": asdict(self.envelope), "pad_ids": list(self._pad_ids),
                "source_ids": list(self._sources), "aliases": dict(self._aliases),
                "plans": {k: {"phase": s.phase, "plan_digest": s.digest,
                               "emitted": sorted(s.emitted)} for k, s in self._plans.items()},
                "pending_plans": [k for k, s in self._plans.items() if s.phase != "COMPLETE"],
                "visible_row_ids": list(self._observed_rows),
                "pad_relation_ids": list(self._relation_rows),
                "current_capability": [list(r) for r in self._capability(False)],
                "potential_capability": [list(r) for r in self._capability(True)],
                "target_ids": list(self._targets), "callback_count": self.callback_count,
                "contract_violation": self._contract_violation, "queued_observations": len(self._ingest_queue),
                "certification": self._guard(self._capability(True)) or {"status": "PROTECTED"},
                "restoration_implemented": "joint_pad_linear_span_only"}
