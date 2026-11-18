#!/usr/bin/env python3
"""Replay stored public affine fixtures, then compare outside recovery."""
from __future__ import annotations

import argparse
import ast
import copy
import inspect
import json
from pathlib import Path

import affine_replay as implementation
from affine_replay import (compile_affine, recover_affine, digest, curve, prior,
                           R, H_HANDLE)

HERE = Path(__file__).resolve().parent


def load_fixture(name, directory=HERE):
    fixture = json.loads((directory/"fixtures"/(name+".json")).read_text())
    expected = json.loads((directory/"expected"/(name+".json")).read_text())
    return fixture, expected


def main(directory=HERE):
    manifest = json.loads((directory/"fixtures"/"manifest.json").read_text())
    backend = curve.validate_backend()
    positives, negatives, invariance = [], [], []
    cached = {}

    def verify_candidate(fixture, expected):
        before = digest(fixture)
        pp, target, ledger = (fixture["public_setup"], fixture["original_target"],
                              fixture["observer_ledger"])
        compiled = compile_affine(pp, target, ledger)
        if compiled["status"] != "REPRESENTED_CANDIDATE":
            raise AssertionError("Expected represented witness: " + fixture["name"])
        replay = recover_affine(pp, target, ledger, compiled["recipe"])
        if replay["GT_hex"] != expected["GT_hex"] or replay["key_sha256"] != expected["key_sha256"]:
            raise AssertionError("Original encapsulator GT/key comparison failed: " + fixture["name"])
        if before != digest(fixture):
            raise AssertionError("Compiler or recovery mutated its original input")
        if replay["gamma_times_x"] != R-1 or replay["q_leading_coefficient"] != R-1:
            raise AssertionError("The required normalization sign was lost")
        return {"name": fixture["name"], "status": "AFFINE_TINY_CURVE_REPLAY_VERIFIED",
                "public_fixture_sha256": before, "expected_output_sha256": digest(expected),
                "original_input_unchanged": True, "GT_match": True, "key_match": True,
                "compiled": compiled, "replay": replay}, compiled

    for name in manifest["positive_cases"]:
        fixture, expected = load_fixture(name, directory)
        result, compiled = verify_candidate(fixture, expected)
        positives.append(result)
        cached[name] = (fixture, expected, compiled)

        # This changes only the observer's coordinate ordering and redundant
        # equations, never the frozen target, ciphertext, or KDF context.
        permuted = copy.deepcopy(fixture)
        ledger = permuted["observer_ledger"]
        ledger["source_ids"].reverse()
        ledger["points"].reverse()
        ledger["equations"].reverse()
        if ledger["equations"]:
            extra = copy.deepcopy(ledger["equations"][0])
            extra["equation_id"] += "-redundant-times-two"
            extra["evidence_id"] += "-same-known-equation-scaled"
            extra["terms"] = {key: 2*value % R for key, value in extra["terms"].items()}
            extra["rhs"] = 2*extra["rhs"] % R
            ledger["equations"].append(extra)
        reordered, _ = verify_candidate(permuted, expected)
        if digest(permuted["original_target"]) != digest(fixture["original_target"]):
            raise AssertionError("Ordering test changed the original target")
        invariance.append({"name": name, "result": "same original GT and key",
                           "original_target_unchanged": True,
                           "x": reordered["replay"]["x"],
                           "q": reordered["replay"]["q"]})

    def reject(name, base, action, change):
        try:
            action()
        except ValueError as error:
            negatives.append({"name": name, "base_fixture": base, "change": change,
                              "classification": "REJECTED", "reason": str(error)})
        else:
            raise AssertionError("Expected explicit rejection: " + name)

    def no_representation(name, fixture, change):
        result = compile_affine(fixture["public_setup"], fixture["original_target"],
                                fixture["observer_ledger"])
        if result["status"] != "NO_REPRESENTED_WITNESS_IN_SUPPLIED_SPAN":
            raise AssertionError("Expected no witness in supplied span: " + name)
        negatives.append({"name": name, "base_fixture": fixture["name"], "change": change,
                          "classification": result["status"], "diagnostic": result["diagnostic"]})

    def wrong_candidate(name, fixture, expected, change):
        result = compile_affine(fixture["public_setup"], fixture["original_target"],
                                fixture["observer_ledger"])
        if result["status"] != "REPRESENTED_CANDIDATE":
            raise AssertionError("Expected a formal candidate for the wrong metadata test")
        replay = recover_affine(fixture["public_setup"], fixture["original_target"],
                                fixture["observer_ledger"], result["recipe"])
        if replay["GT_hex"] == expected["GT_hex"] or replay["key_sha256"] == expected["key_sha256"]:
            raise AssertionError("Wrong data unexpectedly matched the original output: " + name)
        negatives.append({"name": name, "base_fixture": fixture["name"], "change": change,
                          "classification": "CANDIDATE_GT_AND_KEY_MISMATCH",
                          "GT_match": False, "key_match": False,
                          "compiled": result, "candidate": replay})

    def compile_copy(fixture):
        return compile_affine(fixture["public_setup"], fixture["original_target"],
                              fixture["observer_ledger"])

    def replay_copy(fixture, recipe):
        return recover_affine(fixture["public_setup"], fixture["original_target"],
                              fixture["observer_ledger"], recipe)

    for base in ["mixed_masks_with_actual_rhs", "numerical_pad_point_cancellation"]:
        changed = copy.deepcopy(cached[base][0])
        changed["observer_ledger"]["points"] = []
        no_representation(base+"_missing_point", changed, "Remove the needed observed mask or pad point; public h remains available.")

    private, _ = load_fixture(manifest["unopened_offset_negative"], directory)
    no_representation("private_offset_retained_as_free_source", private,
                      "No public equation opens the offset; its realized value is absent from the observer input.")

    changed = copy.deepcopy(private)
    changed["observer_ledger"]["equations"].append({
        "equation_id": "private-audit-offset", "evidence_id": "instrumented-audit-only",
        "visibility": "auditor_only", "terms": {"offset": 1}, "rhs": 17})
    reject("private_rhs_cannot_be_used_for_elimination", private["name"],
           lambda: compile_copy(changed), "Inject offset=17 with auditor_only visibility; reject instead of using its RHS.")

    changed = copy.deepcopy(private)
    changed["observer_ledger"]["points"][0]["expression"] = {
        "visibility": "auditor_only", "constant": 17, "terms": {"v1": 1}}
    reject("private_offset_cannot_be_relabelled_as_constant", private["name"],
           lambda: compile_copy(changed), "Use the audit-only offset in an affine constant descriptor; reject its provenance.")

    base = "known_point_affine_offset"
    fixture, expected, compiled = cached[base]
    h_index = compiled["recipe"]["point_handle_ids"].index(H_HANDLE)
    recipe = copy.deepcopy(compiled["recipe"])
    recipe["point_coefficients"][h_index] = 0
    reject("missing_required_affine_constant_correction", base,
           lambda: replay_copy(fixture, recipe), "Omit the nonzero h coefficient from the otherwise valid recovery recipe.")
    recipe = copy.deepcopy(compiled["recipe"])
    recipe["point_coefficients"][h_index] = (recipe["point_coefficients"][h_index]+1) % R
    reject("wrong_affine_constant_in_recipe", base,
           lambda: replay_copy(fixture, recipe), "Add one to the required h coefficient; full affine matching rejects.")

    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["points"][0]["expression"]["constant"] += 1
    wrong_candidate("incorrect_point_offset_metadata", changed, expected,
                    "Declare offset 18 for the actual observed point with offset 17; provenance truth is intentionally false.")
    changed = copy.deepcopy(fixture)
    entry = changed["observer_ledger"]["points"][0]
    entry["point"] = prior.point_hex(curve.add(prior.point(entry["point"]), prior.point(fixture["public_setup"]["h"])))
    wrong_candidate("incorrect_point_handle_with_correct_descriptor", changed, expected,
                    "Add h to the supplied point while preserving its affine descriptor.")

    base = "known_numerical_core"
    fixture, expected, compiled = cached[base]
    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["equations"][0]["rhs"] = 0
    wrong_candidate("discard_actual_nonzero_rhs", changed, expected,
                    "Replace the visible answer v1=4 by v1=0; recompile but the original ciphertext remains fixed.")

    base = "aliased_source_affine_sums"
    fixture, expected, compiled = cached[base]
    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["aliases"] = []
    changed["observer_ledger"]["source_ids"] += ["shared-A", "shared-B"]
    no_representation("no_inferred_alias_from_point_values_or_names", changed,
                      "Treat shared-A and shared-B as distinct declared sources without alias evidence, even though the fixture used equal values.")

    base = "three_slot_affine_residual"
    fixture, expected, compiled = cached[base]
    recipe = copy.deepcopy(compiled["recipe"])
    recipe["x"] = [-value % R for value in recipe["x"]]
    recipe["point_coefficients"] = [-value % R for value in recipe["point_coefficients"]]
    reject("gamma_plus_one_wrong_sign", base, lambda: replay_copy(fixture, recipe),
           "Negate a valid x and all L coefficients: affine matching still holds, but gamma*x becomes +1.")
    changed = copy.deepcopy(fixture)
    changed["original_target"]["residual_visibility"] = "auditor_only"
    reject("private_residuals_are_not_observer_coefficients", base,
           lambda: compile_copy(changed), "Mark the residual data as auditor-only instead of giving observer-available residuals.")

    changed = copy.deepcopy(fixture)
    changed["original_target"]["C1"] = prior.point_hex(curve.add(prior.point(changed["original_target"]["C1"]), curve.G))
    reject("changed_original_ciphertext", base, lambda: compile_copy(changed), "Change C1 without changing the bound original context.")
    changed = copy.deepcopy(fixture)
    changed["original_target"]["c"][0] += 1
    reject("changed_original_target_constant", base, lambda: compile_copy(changed), "Change c[0] without changing the bound original affine model.")
    changed = copy.deepcopy(fixture)
    target = changed["original_target"]
    target["projections"][0][-1] = prior.point_hex(curve.add(prior.point(target["projections"][0][-1]), curve.G))
    target["context_object"]["projections"] = copy.deepcopy(target["projections"])
    target["context_hex"] = prior.canonical_json(target["context_object"]).hex()
    reject("last_projection_is_checked", base, lambda: compile_copy(changed),
           "Alter the highest-index projection in a negative-test copy and rebind its context so validation reaches the pairing check.")
    changed = copy.deepcopy(fixture)
    changed["public_setup"]["A"][0] = prior.point_hex(curve.add(prior.point(changed["public_setup"]["A"][0]), curve.G))
    reject("changed_setup_old_digest", base, lambda: compile_copy(changed), "Change a public setup point while retaining the original setup digest.")
    changed = copy.deepcopy(fixture)
    changed["original_target"]["context_hex"] += "00"
    reject("changed_original_context_bytes", base, lambda: compile_copy(changed), "Append a byte to the original KDF context.")

    base = "opened_offset_actual_rhs"
    fixture, expected, compiled = cached[base]
    changed = copy.deepcopy(fixture)
    duplicate = copy.deepcopy(changed["observer_ledger"]["equations"][0])
    duplicate["equation_id"] += "-contradiction"
    duplicate["rhs"] += 1
    changed["observer_ledger"]["equations"].append(duplicate)
    reject("inconsistent_visible_affine_fiber", base, lambda: compile_copy(changed), "Add offset=18 alongside the already visible offset=17.")
    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["audit_only_values"] = {"offset": 17}
    reject("extra_private_audit_payload_not_accepted", base, lambda: compile_copy(changed),
           "Attach a separate audit payload to an API which accepts only the exact observer-ledger schema.")
    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["points"][0]["visibility"] = "auditor_only"
    reject("private_point_handle_not_available", base, lambda: compile_copy(changed), "Mark a needed point handle as auditor-only.")
    changed = copy.deepcopy(fixture)
    changed["observer_ledger"]["equations"][0]["rhs"] += 1
    reject("stale_recipe_after_rhs_change", base,
           lambda: replay_copy(changed, compiled["recipe"]), "Reuse a compiled recipe after the observer ledger RHS has changed.")

    # Distinguish a wrong KDF context from a wrong group element, and verify
    # the multiplicative-target translation of the paper's additive notation.
    fixture, expected, compiled = cached["known_numerical_core"]
    replay = recover_affine(fixture["public_setup"], fixture["original_target"],
                            fixture["observer_ledger"], compiled["recipe"])
    target = fixture["original_target"]
    z = curve.decode_gt(bytes.fromhex(replay["GT_hex"]))
    if prior.key_derive(bytes.fromhex(target["context_hex"])+b"different", z) == expected["key_sha256"]:
        raise AssertionError("Wrong KDF context matched")
    negatives.append({"name": "same_gt_different_kdf_context", "base_fixture": fixture["name"],
                      "classification": "KEY_MISMATCH_WITH_SAME_GT",
                      "GT_match": True, "key_match": False})
    wrong_z = (curve.pairing(prior.point(target["C0"]), prior.point(replay["R_h"]))
               / curve.pairing(prior.point(target["C1"]), prior.point(replay["Q_h"])))
    if wrong_z.encode().hex() == expected["GT_hex"]:
        raise AssertionError("Opposite pairing sign matched")
    negatives.append({"name": "opposite_sign_on_second_pairing", "base_fixture": fixture["name"],
                      "classification": "GT_MISMATCH", "GT_match": False,
                      "wrong_GT_hex": wrong_z.encode().hex()})

    source = inspect.getsource(implementation.recover_affine)
    identifiers = {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
    forbidden = {"source_values", "setup_private", "encapsulation_scalar", "expected_encapsulator_output"}
    if identifiers & forbidden:
        raise AssertionError("Private generator input is referenced by recovery")
    source_module = Path(implementation.__file__).read_text()
    calls = {node.func.attr for node in ast.walk(ast.parse(source_module))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    if calls & {"setup", "make_fixture", "make_all", "build"}:
        raise AssertionError("Recovery module calls a private fixture generator")
    api_review = {"recover_signature": str(inspect.signature(recover_affine)),
                  "compile_signature": str(inspect.signature(compile_affine)),
                  "forbidden_private_identifiers_absent_from_recover": True,
                  "recovery_module_does_not_call_fixture_generator": True,
                  "expected_outputs_loaded_only_by_outer_comparator": True,
                  "original_target_and_public_fixture_unchanged_in_every_positive": True,
                  "note": "Static checks support the boundary; provenance labels do not authenticate false metadata."}
    raw = {"schema": "CHARE-affine-replay-results-v1", "field_order": R,
           "backend_checks": backend, "positive_cases": positives,
           "positive_case_count": len(positives), "negative_cases": negatives,
           "negative_case_count": len(negatives),
           "coordinate_invariance_checks": invariance,
           "coordinate_invariance_count": len(invariance), "api_review": api_review,
           "scope": "Independent actual tiny-curve diagnostic; no original PBC/native/security-level/performance claim."}
    (directory/"raw_results.json").write_text(json.dumps(raw, indent=2, sort_keys=True)+"\n")
    (directory/"api_review.json").write_text(json.dumps(api_review, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"positive_case_count": len(positives), "negative_case_count": len(negatives),
                      "coordinate_invariance_count": len(invariance),
                      "all_original_GT_and_key_comparisons_passed": True,
                      "result": str(directory/"raw_results.json")}, indent=2))
    return raw


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=HERE)
    arguments = parser.parse_args()
    main(arguments.directory)
