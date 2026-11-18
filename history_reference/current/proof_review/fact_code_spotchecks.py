#!/usr/bin/env python3
"""Read-only targeted review of round-3 fact evidence and tiny-curve replay.

This imports the delivered reference implementations, writes only its own JSON,
and does not rerun their full fixtures, tests, or benchmark suites.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROUND3 = HERE.parent
sys.path.insert(0, str(ROUND3))

from fact_audit.fact_audit import (FactAuditError, audit_pair, audit_span, compile_ledger,
                                   verify_evidence, verify_history_extension)
import fact_curve_replay as replay


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rejected(fn):
    try:
        fn()
    except (ValueError, KeyError, TypeError) as exc:
        return {"rejected": True, "reason": str(exc)}
    raise AssertionError("A deliberately invalid certificate or transition was accepted")


def main():
    histories = json.loads((ROUND3 / "fact_audit/fixtures.json").read_text())["histories"]
    by_name = {h["history_id"]: h for h in histories}
    span_stage = by_name["family_span_and_conservative_superset"]["stages"][-1]
    p = compile_ledger(span_stage["ledger"])
    q = span_stage["query"]
    evidence = audit_span(p, q["difference_vectors"], q["span_relation"], q.get("actual_pairs"))
    assert evidence["family_status"] == "UNCERTIFIED_SUPERSET"
    mutations = {
        "family_status": "COMPATIBLE_EXACT_SPAN",
        "actual_pair_failure_ids": ["invented-actual-pair"],
        "span_relation": "unknown-relation",
        "execution_status": "PAIRING_TEST_RECIPE_READY",
    }
    tamper = {}
    for key, value in mutations.items():
        bad = copy.deepcopy(evidence)
        bad[key] = value
        tamper[key] = rejected(lambda: verify_evidence(p, bad))

    pending = by_name["pending_canonical_point"]["stages"]
    old = compile_ledger(pending[0]["ledger"])
    new = compile_ledger(pending[1]["ledger"])
    extension = verify_history_extension(old, new)
    rebound = copy.deepcopy(pending[1]["ledger"])
    rebound["sources"][0]["fact_map"] = [0] * len(rebound["fact_ids"])
    rebound_check = rejected(lambda: verify_history_extension(old, compile_ledger(rebound)))

    replay_inputs = json.loads((ROUND3 / "fact_curve/public_replay_inputs.json").read_text())
    # Saved entries must be snapshots: an alternate-tau fixture must not mutate
    # a ledger already appended for the preceding setup.
    for supplied in replay_inputs:
        bound_problem = compile_ledger(supplied["ledger"])
        assert bound_problem.setup_id == supplied["public_setup"]["setup_id"]
        assert bound_problem.ledger_digest == supplied["public_view"]["ledger_digest"]
        assert verify_evidence(bound_problem, supplied["evidence"])
    picked = [x for x in replay_inputs if x["case"].startswith("joint_affine_mixed_system/joint_scalar_and_points/")]
    picked += [next(x for x in replay_inputs if x["case"].startswith("formal_nonzero_fixed_tau_collision/") and x["case"].endswith("tau=3"))]
    picked += [next(x for x in replay_inputs if x["case"].startswith("pending_canonical_point/before_canonical_point/"))]
    outcomes = []
    for supplied in picked:
        # Expected status is read only by this outer comparison, never supplied
        # to the executor whose arguments are precisely the public API inputs.
        actual = replay.execute_fact_test(supplied["public_setup"], supplied["ledger"],
                                          supplied["evidence"], supplied["public_view"])
        assert actual["status"] == supplied["execution_result"]["status"]
        assert actual["native_replay_verified"] is False
        outcomes.append({"case": supplied["case"], "status": actual["status"],
                         "actual_curve_test_executed": actual.get("actual_curve_test_executed", False)})

    coupling_history = by_name["joint_affine_mixed_system"]
    coupling_stage = coupling_history["stages"][0]
    private = copy.deepcopy(coupling_history["fixture_private_diagnostics"])
    initial = compile_ledger(coupling_stage["ledger"])
    pp = replay.fixture_setup(initial.N, private["tau"], private["beta"])
    raw = copy.deepcopy(coupling_stage["ledger"])
    raw["setup_id"] = pp["setup_id"]
    problem = compile_ledger(raw)
    query = coupling_stage["query"]
    cert = audit_pair(problem, query["y0"], query["y1"], query["pair_contract"])
    coupling, _ = replay.compatible_curve_coupling(pp, problem, cert, private)
    assert coupling["status"] == "ACTUAL_CURVE_PUBLIC_VIEWS_EQUAL"

    result = {
        "schema": "CHARE_ROUND3_INDEPENDENT_CODE_SPOTCHECKS_V1",
        "review_date": "2026-11-15", "all_passed": True,
        "scope": "Four status-tamper rejections, an accepted pending publication, rejected source rebinding, all saved replay bindings, four selected public replay calls, and one explicitly private offline coupling; not a full implementation verification",
        "files_sha256": {str(path.relative_to(ROUND3)): file_hash(path) for path in (
            ROUND3 / "fact_audit/fact_audit.py", ROUND3 / "fact_audit/fixtures.json",
            ROUND3 / "fact_curve_replay.py", ROUND3 / "fact_curve/public_replay_inputs.json")},
        "pre_fix_verifier_bug": {
            "source_sha256": "8b31a19ef99f13edcd1d21ba754469648aadd3adc2c9fd78d012a661e1b7d8dc",
            "reproduced": True,
            "behavior": "Changing UNCERTIFIED_SUPERSET to COMPATIBLE_EXACT_SPAN was accepted by verify_evidence",
            "classification": "reference-evidence validation bug, not a counterexample to thm:facts",
        },
        "pre_fix_public_replay_snapshot_bug": {
            "source_sha256": "6af4207beb6f833a45fb1ba1e387614757bd1f7ec6344169d3e9f6f683efbebc",
            "reproduced": True,
            "affected_saved_entries": 2,
            "behavior": "Two tau=3 entries retained a mutable raw ledger reference whose setup_id was overwritten by the later tau=4 iteration, while their setup/evidence remained tau=3",
            "classification": "exported replay artifact correctness bug; the executor correctly rejected the mismatched binding",
        },
        "saved_replay_bindings_checked": len(replay_inputs),
        "post_fix_status_tamper_rejections": tamper,
        "pending_publication_transition": extension,
        "rebound_fact_map_rejected": rebound_check,
        "executor_signature": str(inspect.signature(replay.execute_fact_test)),
        "selected_public_replays": outcomes,
        "offline_compatible_coupling": coupling,
        "native_replay_verified": False,
        "remaining_assumptions": [
            "Canonical source descriptors and observation coefficients come from the declared trusted generation provenance.",
            "The caller supplies the valid fixed-pair and common-prefix contracts; these are not cryptographically proved by a boolean input.",
            "The hash identifies the supplied public setup; it is not a proof of correct setup generation.",
            "The curve is the deliberate nonsecurity toy E/F523 with subgroup order 131, not the original PBC artifact.",
        ],
    }
    output = HERE / "fact_code_spotchecks.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(output), "tamper_rejections": len(tamper),
                      "public_replays": len(outcomes), "offline_couplings": 1, "all_passed": True}))


if __name__ == "__main__":
    main()
