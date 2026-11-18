"""Deterministic A2 checks: exact finite-field logic and exponent-model replay.

Run: python check_auditor.py --output results.json
These results are separate from previous-round checks and all native trials.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
from itertools import product
import argparse
import json
from pathlib import Path
import random
import sys

from auditor_core import (ContractError, PointDescriptor, Target, audit, dot,
                          formal_audit, in_span, public_audit,
                          represented_search, verify_certificate)
from exponent_fixture import ExponentFixture


def make_target(target_id="original-target", offsets=(7, 11), known=True):
    return Target(target_id, 101, ("source/core/1", "source/core/2"),
                  ((1, 0), (0, 1)), (0, 0), (100, 1), offsets, known)


def fixture_and_result():
    t = make_target()
    f = ExponentFixture(t, (1, 2, 3, 4), (1, 2), (23, 37))
    f.add_affine("observed/core2", (0, 0, 1), "retained-event/open-core2")
    result = audit(t, [(1, 0), (0, 1)], list(f.descriptors.values()))
    return f, result


def expect_reject(fn, phrase):
    try:
        fn()
    except ContractError as e:
        if phrase not in str(e):
            raise AssertionError((phrase, str(e))) from e
        return str(e)
    raise AssertionError("expected contract rejection")


def main():
    cases = []
    # A first formal witness can use an unrepresented direction. Search the
    # supplied actual point span afresh and recover with a DIFFERENT witness.
    f, r = fixture_and_result()
    assert r["formal"]["x"] == [1, 0]
    assert r["represented"]["x"] == [0, 100]
    replay = f.replay(r)
    assert replay["full_projection_checks"] == 6
    cases.append({"case": "different_represented_witness", "formal_x": r["formal"]["x"],
                  "represented_x": r["represented"]["x"], "replay": replay})

    # A formal polynomial completion must not manufacture a constant point.
    t = Target("pending-target", 101, ("v1", "pending-w2"), ((1,), (0,)),
               (0,), (1,), (0,), True)
    pending = ExponentFixture(t, (1, 2, 3), (1,), (23, 37))
    pending.add_pending("pending/mixed-point", (23 + (13 - 2) * 37) * 17,
                        "retained-event/pending-no-ladder")
    rpending = audit(t, [(1, 0)], list(pending.descriptors.values()))
    assert rpending["status"] == "FORMAL_WITNESS"
    assert rpending["represented"]["state"] == "NO_CANDIDATE_IN_DECLARED_SPAN"
    why = expect_reject(lambda: pending.replay(rpending), "formal witness")
    cases.append({"case": "pending_source_without_ladder", "status": rpending["status"], "replay_rejection": why})

    # Same source, now an actual ladder handle makes v1 h a real recipe.
    pending.add_point("released/pending-ladder", (13 - 2) * 37 * 17)
    derived = (pending.points["pending/mixed-point"] - pending.points["released/pending-ladder"]) % 101
    pending.add_point("derived/v1", derived)
    pending.add_affine("derived/v1", (0, 1, 0),
                       "recipe:pending/mixed-point-minus-released/pending-ladder")
    rcompleted = audit(t, [(1, 0)], list(pending.descriptors.values()))
    assert rcompleted["status"] == "REPRESENTED_CANDIDATE"
    cases.append({"case": "pending_recipe_materialized", "replay": pending.replay(rcompleted)})

    # The conservative public test may fail while exact residuals protect.
    tprotected = replace(make_target(), eta=(9, 0))
    exact = formal_audit(tprotected, [(1, 0)])
    assert exact["status"] == "PROTECTED"
    assert verify_certificate(tprotected, [(1, 0)], exact["z"], exact["a"])
    public = public_audit(tprotected, [(1, 0)], [])
    public_with_D = public_audit(tprotected, [(1, 0)], [0])
    assert public["status"] == "UNCERTIFIED" and public_with_D["status"] == "PROTECTED"
    cases.append({"case": "conservative_false_negative", "exact": exact,
                  "public_empty_D": public, "public_certified_D": public_with_D})

    # The actual affine term is matched in its own row, including known h.
    handles = r["represented"]["selected_handles"]
    weights = r["represented"]["point_coefficients"]
    assert weights[handles.index("h")] == (-11) % 101
    bad = deepcopy(r)
    bad["represented"]["point_coefficients"][handles.index("h")] = 0
    why = expect_reject(lambda: f.replay(bad), "actual affine source term")
    cases.append({"case": "dropped_actual_affine_offset", "rejection": why})

    changed = audit(replace(f.target, offsets=(7, 12)), [(1, 0), (0, 1)], list(f.descriptors.values()))
    why = expect_reject(lambda: f.replay(changed), "original target or actual affine data changed")
    cases.append({"case": "substituted_target_offset", "rejection": why})

    # Knowing ground-truth values in the audit harness is not scalar delivery.
    private = replace(f.target, execution_metadata_known=False)
    private_result = audit(private, [(1, 0), (0, 1)], list(f.descriptors.values()))
    assert private_result["status"] == "FORMAL_WITNESS"
    assert private_result["represented"]["state"] == "SCALAR_PROVENANCE_PENDING"
    cases.append({"case": "audit_only_scalar_data", "status": private_result["status"],
                  "represented_state": private_result["represented"]["state"]})

    # A private descriptor must not block a candidate that does not need it.
    fknown, _ = fixture_and_result()
    private_point = fknown.add_affine("audit-only/core1", (0, 1, 0),
                                     "instrumented-private-description", known=False)
    unused = audit(fknown.target, [(1, 0), (0, 1)], list(fknown.descriptors.values()))
    assert unused["status"] == "REPRESENTED_CANDIDATE"
    assert "audit-only/core1" not in unused["represented"]["selected_handles"]
    cases.append({"case": "unused_audit_only_descriptor", "replay": fknown.replay(unused)})

    # Reordering puts the private direction into the first audit-span solution.
    # The known descriptor span must be solved independently, not filtered by
    # looking at the coefficients of that one solution.
    ordered = [fknown.descriptors["h"], private_point, fknown.descriptors["observed/core2"]]
    alternative = audit(fknown.target, [(1, 0), (0, 1)], ordered)
    assert alternative["represented"]["audit_span_x"] == [1, 0]
    assert alternative["represented"]["x"] == [0, 100]
    cases.append({"case": "alternative_observer_known_descriptor_witness",
                  "audit_span_x": alternative["represented"]["audit_span_x"],
                  "known_span_x": alternative["represented"]["x"],
                  "replay": fknown.replay(alternative)})

    # Acceptance checks use capacity N, even though the recovery formula uses n.
    truncated = [row[:len(f.nodes) - 1] for row in f.projections]
    why = expect_reject(lambda: f.replay(r, projection_handles=truncated), "full N-1")
    cases.append({"case": "cohort_only_projection_validation", "rejection": why})

    fbad, rbad = fixture_and_result()
    top = fbad.projections[0][-1]
    fbad.points[top] = (fbad.points[top] + 1) % 101
    # Model a malformed original record, rather than after-the-fact tampering.
    fbad.original_public_inputs[top] = fbad.encode(fbad.points[top])
    why = expect_reject(lambda: fbad.replay(rbad), "full projection check failed")
    cases.append({"case": "bad_highest_projection", "rejection": why})

    why = expect_reject(lambda: f.replay(r, context=f.original_context + b"different-snapshot"), "KDF context changed")
    cases.append({"case": "changed_original_KDF_context", "rejection": why})

    fbad, rbad = fixture_and_result()
    fbad.points[fbad.C1] = (fbad.points[fbad.C1] + 1) % 101
    why = expect_reject(lambda: fbad.replay(rbad), "ciphertext bytes changed")
    cases.append({"case": "changed_original_ciphertext", "rejection": why})

    fbad, rbad = fixture_and_result()
    del fbad.points["observed/core2"]
    why = expect_reject(lambda: fbad.replay(rbad), "unregistered source handle")
    cases.append({"case": "missing_source_handle", "rejection": why})

    forged = replace(f.descriptors["observed/core2"], source_ids=("new/core1", "new/core2"))
    why = expect_reject(lambda: represented_search(f.target, [forged]), "provenance mismatch")
    cases.append({"case": "source_identity_replacement", "rejection": why})

    why = expect_reject(lambda: audit(f.target, [(1, 0)], list(f.descriptors.values())), "absent from formal capability")
    cases.append({"case": "formal_capability_omits_actual_direction", "rejection": why})

    # n=1, N=1: empty quotient/setup sums are legitimate, not a special attack.
    singleton = Target("singleton", 101, ("v",), ((1,),), (0,), (1,), (5,), True)
    fsingle = ExponentFixture(singleton, (1,), (1,), (23,))
    fsingle.add_affine("observed/v", (0, 1), "retained-event/open-v")
    rsingle = audit(singleton, [(1,)], list(fsingle.descriptors.values()))
    single_replay = fsingle.replay(rsingle)
    assert single_replay["full_projection_checks"] == 0
    cases.append({"case": "singleton_empty_sums", "replay": single_replay})

    # Independent exhaustive oracle over x for small prime-field systems.
    # This verifies new core logic; it does not prove the paper's group theorem.
    rng = random.Random(20261110)
    systems, protected, represented = 240, 0, 0
    for j in range(systems):
        p, d, n = 5, 2, 2
        F = tuple(tuple(rng.randrange(p) for _ in range(n)) for _ in range(d))
        eta = tuple(rng.randrange(2) for _ in range(n))
        offsets = tuple(rng.randrange(p) for _ in range(n))
        U = [tuple(rng.randrange(p) for _ in range(d)) for _ in range(rng.randrange(3))]
        tsmall = Target(f"small/{j}", p, ("w0", "w1"), F, eta, (4, 1), offsets, True)
        fa = formal_audit(tsmall, U)
        admissible = []
        for x in product(range(p), repeat=n):
            if (all(e * v % p == 0 for e, v in zip(eta, x)) and dot(tsmall.gamma, x, p) == p - 1
                    and in_span([dot(row, x, p) for row in F], U, p)):
                admissible.append(x)
        assert (fa["status"] == "FORMAL_WITNESS") == bool(admissible)
        if not admissible:
            protected += 1
            assert verify_certificate(tsmall, U, fa["z"], fa["a"])
        # A random subset of actually represented affine generators; unlike
        # the formal set it may omit h, to test the affine row directly.
        actual_columns = [tuple([rng.randrange(p)] + list(u)) for u in U[:rng.randrange(len(U) + 1)]]
        pts = [PointDescriptor(f"actual/{k}", tsmall.source_ids, u, f"event/{k}", True)
               for k, u in enumerate(actual_columns)]
        ra = represented_search(tsmall, pts)
        brute_represented = any(in_span([dot(offsets, x, p)] + [dot(row, x, p) for row in F], actual_columns, p)
                                for x in admissible)
        assert (ra["state"] == "REPRESENTED_CANDIDATE") == brute_represented
        represented += int(brute_represented)
    return {"round": "A2", "scope": "reference finite-field solver and transparent exponent model only",
            "native_replay": "NOT_RUN", "deterministic_edge_cases": len(cases),
            "cases": cases, "small_field_crosscheck": {"seed": 20261110, "systems": systems,
            "vectors_enumerated": systems * 25, "protected_systems": protected,
            "represented_candidate_systems": represented}, "all_checks_passed": True,
            "run_utc": datetime.now(timezone.utc).isoformat(), "python_version": sys.version,
            "source_sha256": {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                              for name in ("auditor_core.py", "exponent_fixture.py", "check_auditor.py")}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results.json")
    args = parser.parse_args()
    results = main()
    Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: results[k] for k in ("deterministic_edge_cases", "small_field_crosscheck", "native_replay", "all_checks_passed")}, ensure_ascii=False))
