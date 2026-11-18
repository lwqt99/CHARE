# CHARE public coefficient controller — incremental reference implementation

## What is executable here

This module connects public coefficient checks to a **serial, pre-emission callback path**. It preserves immutable source identities, frozen plans, retained partials, aborted plans, future contribution reservations, and pad-only linear observations. It checks canonical service plans against proved moment or reserved-node polynomial spaces. A controlled emitter is invoked only after the public guard passes and the corresponding reservation or possibly-visible row has been committed.

Run the ten deterministic traces with Python 3.10 or newer and the standard library:

```bash
python3 run_checks.py
```

The script writes `controller_summary.json` and `controller_traces.json` beside itself. All ten scenario groups pass. They include the newly identified **pad opening before any contribution** case, over both `p=101` and the same 256-bit subgroup modulus as the previous coordinate reference.

The test callbacks return opaque public handles. These checks are executed controller/dataflow evidence, not native group or KDF replay. A separate coordinate backend can generate the actual points inside the same callbacks and retain their encodings under those handles.

## Files

| File | Purpose |
|---|---|
| `controller.py` | Immutable public descriptors, source binding adapter, serial admission, callback ordering, retained observations and plans. |
| `field.py` | Exact field arithmetic, row spaces, nullspaces, joint pad elimination, interpolation and formal canonical target witnesses. |
| `run_checks.py` | Ten deterministic scenario groups and the explicit trusted-manifest fixture. |
| `controller_summary.json` | Compact actual execution results. |
| `controller_traces.json` | Public event order, decisions, callback counts and coefficient states. |

## Public API

```python
from controller import (
    Controller, SourceRecord, Envelope, PadEdge, MaskPair,
    Plan, CanonicalTarget,
)

controller = Controller(
    p=prime_order,
    setup_nodes=(1, 2, 3, 4, 5, 6),
    cores=[(public_core_record, authenticated_receipt), ...],
    envelope=Envelope(dimension=2),
    binding_verifier=verify_public_generation_binding,
    prime_is_prevalidated=True,  # required only for a modulus >= 2**64
)
```

The original parameter profile supplies the prime-field assumption for a large modulus. This module performs no domain enumeration and introduces no curve-security or primality-certificate claim. Small moduli below `2**64` are checked by the deterministic 64-bit Miller–Rabin basis set.

| Method | Action |
|---|---|
| `install_source(source, receipt, expected_revision)` | Add a mask record authenticated by the supplied binding adapter. |
| `register_alias(alias, original_source_id, receipt, expected_revision)` | Bind an alias once to the original physical coordinate. |
| `freeze_plan(plan, expected_revision)` | Validate public coefficients and identity bindings, then reserve every frozen contribution row. |
| `install_pads(plan_id, expected_revision, emitter)` | Invoke the declared pad-installation callback after a current guard and state commit. |
| `emit_contribution(plan_id, source_id, expected_revision, emitter)` | Commit the possibly-visible contribution row, then invoke its emitter. |
| `request_pad_opening(relation_id, coefficients, expected_revision, emitter)` | Check the proposed pad-only row jointly against all retained and possible future contributions; commit before emission. |
| `observe_pad_opening(relation_id, coefficients, payload_handle, expected_revision)` | Retain an already-visible external opening, including stale observations, then audit it. |
| `admit_target(target, expected_revision, emitter)` | Check a new **canonical empty-policy target** against current and frozen possible contributions before encapsulation callback. |
| `enroll_core(source, receipt, next_envelope, expected_revision, emitter)` | Check common roots and containment in a legal next envelope before the new-core callback. |
| `abort_plan(plan_id, expected_revision)` | Keep partials, pad identities and the conservative future reservation. |
| `capability(potential=False)` | Return the current recorded coefficient capability; `True` includes the full frozen contribution superledger. |
| `snapshot()` | Return public state and a separate `certification` result. |

An `emitter` is a zero-argument callable returning a nonempty string that identifies its public output. It may close over private backend state, but the controller neither reads that closure nor receives core values, hidden qualification bits, secret fact pairs, hidden residuals, or a proposed scalar right-hand side. This is an API/dataflow boundary in a single process, not memory isolation or a TEE.

### Immutable descriptors

`SourceRecord` stores only `source_id`, kind, owner/root identity, original node, generation identity, immutable fact identity, generation profile and origin reference. Core records have `fact_id=None`. A mask's `fact_id` must be an immutable nonempty string. The two masks in a `MaskPair` must use distinct physical coordinates and generation identities, bind to the same root/owner/node, and have the same immutable fact identity.

The same attribute name or namespace is not a same-fact binding. An authenticated binding establishes the declared metadata under the honest-generation premise; it is not a proof that arbitrary signed bytes encode independently sampled canonical values.

`Plan` freezes participants, a canonical interpolation polynomial, oriented edges and pad IDs, mask bindings, invocation/direction IDs, and the dictionary epoch. Fields that would otherwise alias mutable lists must be tuples. A graph must be connected. Each absent current node must have zero polynomial weight. Each direction must belong to the current approved envelope.

Physical source and contribution identities use exact tagged JSON serialization, not separator concatenation or hashed equality. Thus IDs containing `:` cannot cause two distinct `(plan_id, physical_source_id)` pairs to overwrite one another. SHA-256 is used only for plan/fixture digests; algebraic row identity does not rely on collision resistance.

## The future contribution guard

For the visible contribution set `S`, assemble all core rows `A` and pad rows `B` in one physical dictionary, across every direction and invocation. Let `L` contain all retained pad-only observation rows. The recorded core capability is

\[
\Phi(S,L)=\{(cA)^\top : c_j=0\text{ for }j\notin S,\ cB\in\operatorname{row}(L)\}.
\]

For prospective admission, replace `S` with the union of all retained rows and **every frozen contribution row that could still become visible**. The code computes the intersection of the mixed-row span generated by `[A B]` and `[0 L]` with the zero-pad subspace. Pad-only points derivable from this same span are already included; re-adding them cannot enlarge the span. This is a linear-algebra closure for this interface, not a delivery or random-oracle restoration engine.

Why complete output directions alone are insufficient: take four current cores, the approved constant direction, and the path `1–2–3–4`. Before any contribution is visible, current core capability is zero, and the planned full sum is safe. If the edge pad between nodes 1 and 2 is opened, a later first contribution yields

\[
C_1-r_{12}h=v_1h.
\]

The ordinary `current + planned full sum` check misses this. The implemented joint future-row check has a nonzero singleton direction and refuses the opening before its callback. The same test is used for cross-call relations such as `r_a-r_b`.

If several potential rows cannot jointly occur, retaining them is a conservative overapproximation. In particular, this reference keeps `ABORTED_RETAINED` and uncertain-emission plans without implementing a protocol that proves they can never complete. A witness in that larger space is not by itself an assertion that one real execution has already recovered a key.

## Approved envelopes and enrollment

For current nodes `P`, reserved unused setup nodes `B`, and dimension `k`, the envelope is

\[
Q_B(X)\{g:\deg g<k\}.
\]

A positive dimension requires `2*k + len(B) <= len(P)`. The zero space is also permitted. `Envelope(k, ())` gives ordinary moments.

Enrollment uses the existing recorded and possible contribution capability, interpolates each basis direction on the original current nodes, and checks it vanishes at the proposed node. It then zero-extends those rows and checks containment in the declared next envelope. Unconsumed reserved-node promises must stay unchanged. Existing core IDs and original target columns are not renamed or resampled. New plans must use the new dictionary epoch; old frozen plans retain their original identities and may finish under the checked next envelope.

## Serial semantics and exceptional events

- Controlled changes require `expected_revision == controller.revision`. A stale request is refused before any private callback.
- A guard pass is followed by a state commit and revision increment, then `PRIVATE_CALLBACK_BEGIN`. The trace records this order.
- A pad opening is committed **before** invoking its emitter. A callback exception cannot roll back an opening that may already have leaked.
- Contribution rows are also recorded as possibly visible before the callback. Exceptions retain the row and mark the plan uncertain.
- Mutating controlled calls during a callback are refused. An already-visible external pad opening is queued instead of discarded; the serial dispatcher drains this queue on callback exit and performs a new audit.
- An already-visible external opening is retained even if its sender used a stale revision. This ingestion path is not a pre-release approval API.
- Unknown or malformed already-visible descriptors are retained as public event records and make subsequent protection uncertified. A malformed replay is not silently filtered into an earlier valid relation.
- The queue and state are in memory. This is not a crash-persistent or distributed controller.

Normally, when callback receipts are complete, `capability(False)` is the exact coefficient capability for the declared visible row/observation set. After an uncertain callback, it is a conservative upper bound that includes possibly-visible rows and precommitted openings. `capability(True)` additionally includes every retained future reservation.

## Decision meanings

| Status/field | Meaning |
|---|---|
| `ADMITTED` | The controlled operation passed the public guard and was committed. If an uncontrolled event occurred during its callback, consult `post_callback_audit`. |
| `RECORDED` | An already-visible observation was retained; this does not mean it is safe. |
| `REPLAY` | An original identity is reused without a new independent coordinate or a repeated private emitter. |
| `UNCERTIFIED` | The public interface or envelope cannot certify the request; this is not a mathematical attack claim. |
| `FORMAL_FAILURE` | There is a nonzero canonical target functional in the stated, possibly conservatively completed coefficient space. This is not native key recovery. |
| `EMISSION_UNCERTAIN` | A callback failed after the precommit; its possibly-visible data remains accounted for. |
| `Decision.accepted` | The operation/record was accepted. It is **not** the security predicate. |
| `snapshot()['certification']` | The separate protection audit for the current possible-completion space. |

This module never emits `RECOVERY_VERIFIED`. The target adapter currently supports only the canonical empty-policy target, whose core map and zero residual are public. General hidden-policy target auditing, true affine delivery restoration, and cryptographic group/KDF verification remain separate components.

## Authentication adapter and sampling premise

`binding_verifier(public_descriptor, public_receipt)` is required. An application should connect its existing authenticated generation path. Tests use an explicit trusted public-manifest fixture so the source of the assumption is reviewable. They do not claim to implement Ed25519, remote attestation, or a new authentication scheme.

Fresh physical pad IDs mean distinct declared independent-sampling events. The controller does not receive pad values and never requires them to be nonzero or pairwise distinct. Independent uniform pads may be zero or numerically equal. Different IDs alone do not prove independent sampling; the declared trusted generation callback remains the premise.
