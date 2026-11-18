#!/usr/bin/env python3
"""Ten deterministic public-controller traces; Python standard library only.

Callback fixtures return opaque public handles. They do not compute real group
points, and this file never reports native recovery. The separate coordinate
backend can use the identical callback API without supplying secret values here.
"""
from dataclasses import asdict, replace
import inspect
import json
from pathlib import Path

from controller import (CanonicalTarget, Controller, Envelope, MaskPair, PadEdge,
                        Plan, SourceRecord, digest, typed_key)
from field import in_span, interpolate, peval

HERE = Path(__file__).resolve().parent
ORIGINAL_PROFILE_P = 83744317841741440616902767845924906116540263821716205350595254709593497412133


class ManifestFixture:
    """Explicit trusted public-manifest adapter; NOT a remote signature scheme."""
    def __init__(self):
        self.approved = {}

    def approve(self, descriptor):
        public = asdict(descriptor) if hasattr(descriptor, "__dataclass_fields__") else descriptor
        h = digest(public)
        receipt = "trusted-manifest:" + h
        self.approved[h] = receipt
        return receipt

    def verify(self, public_descriptor, public_receipt):
        return self.approved.get(digest(public_descriptor)) == public_receipt


class Spy:
    def __init__(self, label="fixture"):
        self.label, self.calls = label, 0

    def __call__(self):
        self.calls += 1
        return "public-handle:" + self.label + ":" + str(self.calls)


def core(i, source_id=None):
    return SourceRecord(source_id or "core:" + str(i), "core", "owner:" + str(i),
                        "root:" + str(i), i, "core-generation:" + str(i), None,
                        "canonical_core_v1", "trusted-constructor:core")


def fixture(r=4, dimension=2, reserved=(), p=101, ids=None):
    auth = ManifestFixture()
    cs = [core(i, ids[i - 1] if ids else None) for i in range(1, r + 1)]
    ctl = Controller(p, tuple(range(1, 9)), [(c, auth.approve(c)) for c in cs],
                     Envelope(dimension, tuple(reserved)), auth.verify,
                     prime_is_prevalidated=p >= 1 << 64)
    return ctl, auth


def plan(ctl, name, polynomial=(1,), cycle=False, participants=None, pairs=()):
    ids = tuple(participants or ctl.snapshot()["core_ids"])
    endpoints = list(zip(ids, ids[1:]))
    if cycle:
        endpoints.append((ids[-1], ids[0]))
    edges = tuple(PadEdge("pad:" + name + ":" + str(j), a, b,
                          "delivery-ref:" + digest([name, j, a, b]))
                  for j, (a, b) in enumerate(endpoints))
    return Plan(name, "invocation:" + name, "direction:" + name,
                ctl.dictionary_epoch, ids, tuple(polynomial), edges, tuple(pairs))


def require_accept(decision):
    assert decision.accepted, decision.to_dict()
    return decision


def freeze_ready(ctl, proposed, spy=None):
    require_accept(ctl.freeze_plan(proposed, ctl.revision))
    require_accept(ctl.install_pads(proposed.plan_id, ctl.revision,
                                  spy or Spy("install:" + proposed.plan_id)))


def complete(ctl, proposed):
    for physical in proposed.participants:
        require_accept(ctl.emit_contribution(proposed.plan_id, physical, ctl.revision,
                                             Spy("contribution:" + physical)))


def deny_without_callback(ctl, operation, expected_reason=None):
    before = ctl.callback_count
    d = operation()
    assert not d.accepted and not d.private_callback_called, d.to_dict()
    assert ctl.callback_count == before
    if expected_reason is not None:
        assert d.reason == expected_reason, d.to_dict()
    return d


def capture(name, ctl, assertions, details=None):
    return {"case": name, "status": "PASS", "assertions": assertions,
            "details": details or {}, "snapshot": ctl.snapshot(), "events": ctl.trace}


def normal_same_fact_lifecycle():
    ctl, auth = fixture()
    pairs = []
    for i in range(1, 5):
        masks = []
        for generation in ("a", "b"):
            m = SourceRecord(f"mask:{i}:{generation}", "mask", f"owner:{i}",
                             f"root:{i}", i, f"mask-generation:{i}:{generation}",
                             f"immutable-fact:{i}:original", "canonical_decision_v1",
                             "trusted-constructor:decision")
            require_accept(ctl.install_source(m, auth.approve(m), ctl.revision))
            masks.append(m.source_id)
        pairs.append(MaskPair(f"core:{i}", *masks))
    target = CanonicalTarget("old-12", ("core:1", "core:2"), "cipher:old-12", "context:old-12")
    require_accept(ctl.admit_target(target, ctl.revision, Spy("target")))
    p = plan(ctl, "normal", pairs=pairs)
    freeze_ready(ctl, p)
    complete(ctl, p)
    assert ctl.snapshot()["plans"][p.plan_id]["phase"] == "COMPLETE"
    assert len(ctl.capability(False)) == 1
    assert ctl.snapshot()["pending_plans"] == []
    before = ctl.callback_count
    replay = ctl.emit_contribution(p.plan_id, "core:1", ctl.revision, Spy("must-not-reemit"))
    assert replay.status == "REPLAY" and ctl.callback_count == before
    for event in ctl.trace:
        if event["event"] == "PRIVATE_CALLBACK_BEGIN":
            prior = ctl.trace[:event["seq"]]
            assert any(e["event"] == "PUBLIC_GUARD_PASS" and e.get("operation") == event["operation"]
                       for e in prior)
            assert prior[-1]["event"] == "COMMIT"
    return capture("01_normal_same_fact_lifecycle", ctl,
                   ["authenticated source bindings", "same immutable fact and distinct generations",
                    "guard and commit precede callback", "complete contribution retained", "replay no resampling"])


def invalid_bindings():
    ctl, auth = fixture()
    wrong = SourceRecord("bad-mask", "mask", "owner:1", "root:1", 1, "m-generation", "fact-a",
                         "canonical_decision_v1", "trusted-constructor:decision")
    deny_without_callback(ctl, lambda: ctl.install_source(wrong, "unapproved", ctl.revision),
                          "AUTHENTICATED_GENERATION_BINDING_FAILED")
    mutable_fact = replace(wrong, source_id="mutable-fact", fact_id=["fact-a"])
    deny_without_callback(ctl, lambda: ctl.install_source(mutable_fact, auth.approve(mutable_fact), ctl.revision),
                          "CANONICAL_MASK_PROFILE_REQUIRED")
    ma = replace(wrong, source_id="mask-a", generation_id="generation-a")
    mb = replace(wrong, source_id="mask-b", generation_id="generation-b", fact_id="fact-b")
    require_accept(ctl.install_source(ma, auth.approve(ma), ctl.revision))
    require_accept(ctl.install_source(mb, auth.approve(mb), ctl.revision))
    bad = plan(ctl, "same-namespace-is-not-same-fact", pairs=(MaskPair("core:1", "mask-a", "mask-b"),))
    deny_without_callback(ctl, lambda: ctl.freeze_plan(bad, ctl.revision),
                          "DISTINCT_IMMUTABLE_FACT_IDENTITIES")
    alias_payload = {"operation": "alias", "alias": "alias:one", "physical_source_id": "core:1"}
    require_accept(ctl.register_alias("alias:one", "core:1", auth.approve(alias_payload), ctl.revision))
    deny_without_callback(ctl, lambda: ctl.register_alias("alias:one", "core:2", "any", ctl.revision),
                          "ALIAS_REBINDING_OR_UNKNOWN_SOURCE")
    assert ctl.snapshot()["aliases"]["alias:one"] == "core:1"
    for cls in (SourceRecord, Plan, CanonicalTarget):
        assert not {"eta", "secret_fact_pair", "raw_core", "candidate_rhs"} & set(inspect.signature(cls).parameters)
    return capture("02_invalid_bindings_and_alias", ctl,
                   ["unapproved generation binding rejected", "same fact identity enforced",
                    "alias cannot rebind physical source", "mutable fact identity rejected",
                    "public dataclasses exclude secret inputs"])


def abort_retry():
    ctl, auth = fixture()
    first = plan(ctl, "first")
    freeze_ready(ctl, first)
    require_accept(ctl.emit_contribution(first.plan_id, "core:1", ctl.revision, Spy("old-partial")))
    require_accept(ctl.abort_plan(first.plan_id, ctl.revision))
    old_rows, old_pads = set(ctl.snapshot()["visible_row_ids"]), set(ctl.snapshot()["pad_ids"])
    reuse = replace(plan(ctl, "retry-bad"), edges=first.edges)
    deny_without_callback(ctl, lambda: ctl.freeze_plan(reuse, ctl.revision),
                          "PAD_ID_REUSE_OR_EDGE_BINDING_ERROR")
    retry = plan(ctl, "retry-new")
    freeze_ready(ctl, retry)
    complete(ctl, retry)
    snap = ctl.snapshot()
    assert old_rows <= set(snap["visible_row_ids"])
    assert old_pads <= set(snap["pad_ids"])
    assert first.plan_id in snap["pending_plans"]
    assert snap["plans"][first.plan_id]["phase"] == "ABORTED_RETAINED"
    return capture("03_abort_retry_retains_sources", ctl,
                   ["old partial survives abort", "aborted reservation survives retry",
                    "old pad identity rejected", "fresh pads allocated without comparing values"])


def pending_enrollment():
    ctl, auth = fixture()
    p = plan(ctl, "pending-constant")
    require_accept(ctl.freeze_plan(p, ctl.revision))
    assert not ctl.capability(False) and len(ctl.capability(True)) == 1
    new = core(5)
    d = deny_without_callback(ctl, lambda: ctl.enroll_core(new, auth.approve(new), Envelope(2),
                                                          ctl.revision, Spy("must-not-enroll")),
                              "PENDING_COMMON_ZERO_CONDITION_FAILED")
    assert "core:5" not in ctl.snapshot()["core_ids"]
    return capture("04_pending_plan_blocks_enrollment", ctl,
                   ["zero visible capability is insufficient", "pending constant has no new common root",
                    "enrollment callback not invoked"], {"decision": d.to_dict()})


def reserved_enrollment():
    ctl, auth = fixture(dimension=1, reserved=(5, 6))
    p = plan(ctl, "reserved", polynomial=(30, -11, 1))
    freeze_ready(ctl, p)
    for physical in p.participants[:2]:
        require_accept(ctl.emit_contribution(p.plan_id, physical, ctl.revision, Spy("partial")))
    new = core(5)
    require_accept(ctl.enroll_core(new, auth.approve(new), Envelope(2, (6,)), ctl.revision, Spy("new-core")))
    for physical in p.participants[2:]:
        require_accept(ctl.emit_contribution(p.plan_id, physical, ctl.revision, Spy("old-plan-late")))
    cap = ctl.capability(False)
    assert len(cap) == 1 and all(row[-1] == 0 for row in cap)
    assert all(in_span(row, ctl.envelope.rows(ctl.nodes, ctl.p), ctl.p) for row in cap)
    stale = plan(ctl, "stale-dictionary", polynomial=(-6, 1))
    stale = replace(stale, dictionary_epoch=0)
    deny_without_callback(ctl, lambda: ctl.freeze_plan(stale, ctl.revision), "STALE_DICTIONARY_EPOCH")
    allowed = plan(ctl, "new-envelope", polynomial=(-6, 1))
    require_accept(ctl.freeze_plan(allowed, ctl.revision))
    return capture("05_reserved_enrollment_and_legal_next_envelope", ctl,
                   ["common root enrollment accepted", "old plan continues with same identities",
                    "old coefficient rows zero extended", "remaining reservation retained",
                    "next envelope accepts new direction", "old dictionary epoch rejected"])


def cycle_opening():
    ctl, auth = fixture()
    p = plan(ctl, "cycle", cycle=True)
    freeze_ready(ctl, p)
    complete(ctl, p)
    require_accept(ctl.request_pad_opening("cycle-first", {p.edges[0].pad_id: 1},
                                          ctl.revision, Spy("one-edge")))
    assert len(ctl.capability(False)) == 1
    d = deny_without_callback(ctl, lambda: ctl.request_pad_opening("cycle-second", {p.edges[1].pad_id: 1},
                                                                   ctl.revision, Spy("must-not-open")),
                              "CANONICAL_TARGET_WITNESS")
    assert ctl.snapshot()["pad_relation_ids"] == ["cycle-first"]
    return capture("06_cycle_allows_one_opening_rejects_next", ctl,
                   ["safe opening actually admitted", "second opening rejected before emission",
                    "no blanket reject-all-openings policy"], {"decision": d.to_dict()})


def future_row_opening():
    records = []
    for modulus in (101, ORIGINAL_PROFILE_P):
        ctl, auth = fixture(p=modulus)
        p = plan(ctl, "future-path")
        freeze_ready(ctl, p)
        visible = ctl.capability(False)
        full_sum = tuple([1] * 4)
        naive_pass = not visible and in_span(full_sum, ctl.envelope.rows(ctl.nodes, ctl.p), ctl.p)
        d = deny_without_callback(ctl, lambda: ctl.request_pad_opening("boundary-before-any-contribution",
                                            {p.edges[0].pad_id: 1}, ctl.revision, Spy("must-not-open")),
                                  "CANONICAL_TARGET_WITNESS")
        assert naive_pass
        assert d.evidence["visible_rank_before"] == 0
        assert d.evidence["potential_rank_after_proposal"] == 2
        records.append(capture("07_future_rows_guard_" + str(modulus.bit_length()) + "bits", ctl,
                               ["current+fullsum naive check passes", "future joint rows find clipped singleton",
                                "no private opening callback", "same guard works over original 256-bit field"],
                               {"naive_current_plus_full_direction_would_admit": True,
                                "decision": d.to_dict()}))
    return {"case": "07_pending_opening_requires_future_rows", "status": "PASS", "subtraces": records}


def cross_call_relation():
    ctl, auth = fixture()
    a, b = plan(ctl, "call-a", polynomial=(1,)), plan(ctl, "call-b", polynomial=(1, 1))
    freeze_ready(ctl, a)
    freeze_ready(ctl, b)
    for p in (a, b):
        require_accept(ctl.emit_contribution(p.plan_id, "core:1", ctl.revision, Spy("partial:" + p.plan_id)))
    assert ctl.capability(False) == ()
    d = deny_without_callback(ctl, lambda: ctl.request_pad_opening("cross-relation",
                                 {a.edges[0].pad_id: 1, b.edges[0].pad_id: -1},
                                 ctl.revision, Spy("must-not-open")), "CANONICAL_TARGET_WITNESS")
    w = d.evidence["witness"]
    assert w["target_indices"] == [0] and w["direction"][0] != 0
    assert all(x == 0 for x in w["direction"][1:])
    return capture("08_cross_call_pad_relation", ctl,
                   ["two individually incomplete calls initially add no core capability",
                    "joint relation rejected", "witness uses same physical core coordinate"],
                   {"decision": d.to_dict()})


def new_target_after_forced_opening():
    ctl, auth = fixture()
    p = plan(ctl, "forced-before-payload")
    freeze_ready(ctl, p)
    stale_revision = 0
    recorded = ctl.observe_pad_opening("forced-edge", {p.edges[0].pad_id: 1}, "already-visible:edge",
                                       stale_revision)
    assert recorded.status == "RECORDED"
    assert ctl.snapshot()["pad_relation_ids"] == ["forced-edge"]
    assert ctl.capability(False) == () and len(ctl.capability(True)) == 2
    target = CanonicalTarget("new-singleton", ("core:1",), "cipher:new", "context:new")
    d = deny_without_callback(ctl, lambda: ctl.admit_target(target, ctl.revision, Spy("must-not-encapsulate")),
                              "NEW_TARGET_UNSAFE_UNDER_PENDING_COMPLETION")
    assert not ctl.snapshot()["target_ids"]
    return capture("09_new_target_checks_pending_and_retains_stale_exposure", ctl,
                   ["already-visible stale observation retained", "new target checks possible contributions",
                    "target callback not invoked", "no claimed prevention of compelled exposure"],
                   {"decision": d.to_dict()})


def revision_identity_callback_failures():
    subtraces = []
    ctl, auth = fixture(ids=("x:y", "y", "z", "w"))
    first, second = plan(ctl, "a"), plan(ctl, "a:x")
    first_revision = ctl.revision
    require_accept(ctl.freeze_plan(first, first_revision))
    deny_without_callback(ctl, lambda: ctl.freeze_plan(second, first_revision), "STALE_REVISION")
    require_accept(ctl.freeze_plan(second, ctl.revision))
    assert typed_key("contribution", "a", "x:y") != typed_key("contribution", "a:x", "y")
    assert len(ctl._rows(True)) == 8
    assert typed_key("installation", "a:x") != typed_key("target", "a:x")
    inner = []
    def reentrant_install():
        inner.append(ctl.abort_plan(first.plan_id, ctl.revision))
        return "public-handle:installed"
    require_accept(ctl.install_pads(first.plan_id, ctl.revision, reentrant_install))
    assert inner[0].reason == "MUTATING_CALLBACK_REENTRY"
    require_accept(ctl.emit_contribution(first.plan_id, "x:y", ctl.revision, Spy("one")))
    require_accept(ctl.install_pads(second.plan_id, ctl.revision, Spy("install-two")))
    require_accept(ctl.emit_contribution(second.plan_id, "y", ctl.revision, Spy("two")))
    assert len(ctl.snapshot()["visible_row_ids"]) == 2
    subtraces.append(capture("typed_identity_stale_revision_and_reentry", ctl,
                            ["separator-containing IDs do not collide", "stale request cannot emit",
                             "controlled callback reentry rejected", "two physical rows retained"]))

    ctl, auth = fixture()
    p = plan(ctl, "exception-cycle", cycle=True)
    freeze_ready(ctl, p)
    complete(ctl, p)
    def may_have_published():
        raise RuntimeError("PRIVATE EXCEPTION TEXT MUST NEVER ENTER THE TRACE")
    failed = ctl.request_pad_opening("uncertain-first", {p.edges[0].pad_id: 1}, ctl.revision,
                                    may_have_published)
    assert failed.status == "EMISSION_UNCERTAIN" and failed.private_callback_called
    assert "uncertain-first" in ctl.snapshot()["pad_relation_ids"]
    deny_without_callback(ctl, lambda: ctl.request_pad_opening("unsafe-after-exception",
                          {p.edges[1].pad_id: 1}, ctl.revision, Spy("must-not-open")))
    assert "PRIVATE EXCEPTION TEXT" not in json.dumps(ctl.trace)
    subtraces.append(capture("callback_exception_does_not_rollback_opening", ctl,
                            ["opening row committed before callback", "exception retains possible exposure",
                             "subsequent unsafe opening denied", "exception body not leaked in log"]))

    ctl, auth = fixture()
    p = plan(ctl, "queued-cycle", cycle=True)
    freeze_ready(ctl, p)
    complete(ctl, p)
    def observes_external_during_callback():
        q = ctl.observe_pad_opening("external-queued", {p.edges[1].pad_id: 1},
                                    "already-visible:queued", 0)
        assert q.reason == "VISIBLE_OBSERVATION_QUEUED_FOR_SERIAL_DRAIN"
        return "public-handle:first-opening"
    outcome = ctl.request_pad_opening("controlled-first", {p.edges[0].pad_id: 1}, ctl.revision,
                                      observes_external_during_callback)
    assert set(ctl.snapshot()["pad_relation_ids"]) == {"controlled-first", "external-queued"}
    assert ctl.snapshot()["queued_observations"] == 0
    assert outcome.evidence["post_callback_audit"]["status"] == "FORMAL_FAILURE"
    subtraces.append(capture("already_visible_callback_queue_is_drained", ctl,
                            ["external reentrant observation queued instead of discarded",
                             "stale external observation retained after callback",
                             "post-callback breach reported, not silently protected"]))
    ctl, auth = fixture()
    p = plan(ctl, "malformed-replay", cycle=True)
    freeze_ready(ctl, p)
    complete(ctl, p)
    require_accept(ctl.request_pad_opening("original-relation", {p.edges[0].pad_id: 1},
                                          ctl.revision, Spy("safe-opening")))
    bad_replay = ctl.observe_pad_opening("original-relation",
                                         {p.edges[0].pad_id: 1, "unmodeled-extra": [1]},
                                         "already-visible:malformed", ctl.revision)
    assert bad_replay.status == "UNCERTIFIED"
    assert ctl.snapshot()["contract_violation"]
    assert ctl.snapshot()["certification"]["status"] == "UNCERTIFIED"
    assert any(e["event"] == "UNMODELED_VISIBLE_PAYLOAD" for e in ctl.trace)
    subtraces.append(capture("malformed_replay_is_not_silently_filtered", ctl,
                            ["full descriptor validated before replay comparison",
                             "already-visible malformed payload retained and uncertified"]))
    return {"case": "10_revision_identity_and_callback_boundary", "status": "PASS", "subtraces": subtraces}


def main():
    cases = [normal_same_fact_lifecycle, invalid_bindings, abort_retry, pending_enrollment,
             reserved_enrollment, cycle_opening, future_row_opening, cross_call_relation,
             new_target_after_forced_opening, revision_identity_callback_failures]
    results = [case() for case in cases]
    output = {"status": "PASS", "case_count": len(results),
              "evidence_level": "executed_public_coefficient_controller_and_callback_order",
              "native_group_recovery": False,
              "full_random_oracle_delivery_restoration": False,
              "authentication_fixture": "explicit trusted public manifest; no signature implementation claim",
              "field_profiles": ["p=101", "same 256-bit p as prior coordinate reference"],
              "cases": results}
    (HERE / "controller_traces.json").write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    summary = {k: v for k, v in output.items() if k != "cases"}
    summary["cases"] = [{"case": x["case"], "status": x["status"]} for x in results]
    (HERE / "controller_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
