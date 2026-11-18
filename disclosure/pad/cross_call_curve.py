#!/usr/bin/env python3
"""New A2 cross-call fixture on an explicitly supplied, reused Curve backend.

Two separate processes:
  generate: samples private values with secrets.randbelow; exports only public
            points/metadata, the intentional scalar pad relation, and a separate
            expected-digest file. No private scalar or generation seed is saved.
  replay:   recovers from that public fixture before opening expected digests.

This is a Python coordinate functionality check. It is not a native Go/PBC run,
does not test authenticated transport, and does not establish a security level.
The Curve backend is a declared external dependency; it is not copied here.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import time
from pathlib import Path

from joint_pad_reference import inspect_ledger, verify_certificate
from verify_joint_pad import cross_call_ledger


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_backend(path):
    specification = importlib.util.spec_from_file_location("chare_a2_declared_curve_backend", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, digest(path.read_bytes())


def encode_point(point):
    return {"infinity": True} if point is None else {"x": str(point[0]), "y": str(point[1])}


def decode_point(point):
    return None if point.get("infinity") else (int(point["x"]), int(point["y"]))


def gt_record(value):
    return {"a": str(value[0]), "b": str(value[1])}


def signed(value, prime):
    value %= prime
    return value-prime if value > prime//2 else value


def reference_kdf(context, encoded_gt):
    # An explicit deterministic functional stand-in, not an implementation of
    # the paper's random oracle or a claim about a deployed KDF protocol.
    return hashlib.sha256(b"CHARE-A2-REFERENCE-KDF-v1\0" +
                          len(context).to_bytes(8, "big") + context + encoded_gt).hexdigest()


def wrong_pad_answer_control(zero_randomizer, recovered_digest, wrong_digest):
    if zero_randomizer:
        if wrong_digest != recovered_digest:
            raise AssertionError("identity C0 should make both recovery inputs the identity")
        return "ZERO_RANDOMIZER_CONTROL"
    if wrong_digest == recovered_digest:
        raise AssertionError("nonidentity C0 did not distinguish the changed pad answer")
    return "PASS"


def generator_point(curve):
    cofactor = (curve.q+1)//curve.p
    while True:
        x = secrets.randbelow(curve.q)
        rhs = (x*x*x+x) % curve.q
        y = pow(rhs, (curve.q+1)//4, curve.q)
        if y*y % curve.q != rhs:
            continue
        result = curve.mul((x, y), cofactor)
        if result is not None and curve.valid(result):
            return result


def generate(arguments):
    started = time.monotonic()
    module, backend_hash = load_backend(arguments.backend)
    old_parameters = json.loads(arguments.parameters.read_text())
    parameters = {key: old_parameters[key] for key in ("p", "q", "cofactor", "p_bits", "q_bits")}
    parameters["curve"] = "y^2=x^3+x over F_q; same public parameter values as supplied backend artifact"
    curve = module.Curve(parameters)
    p = curve.p
    g = generator_point(curve)
    a, theta = 1+secrets.randbelow(p-1), 1+secrets.randbelow(p-1)
    alpha, s = secrets.randbelow(p), secrets.randbelow(p)
    tau = secrets.randbelow(p)
    while tau in (0, 1, 2, 3, 4):
        tau = secrets.randbelow(p)
    cores = [secrets.randbelow(p) for _ in range(4)]
    pads = [secrets.randbelow(p) for _ in range(6)]
    h = curve.mul(g, theta)
    y3 = curve.mul(g, a*pow(tau, 3, p) % p)
    root_points = [curve.mul(g, value) for value in cores]
    gamma = curve.mul(h, (alpha+a*pow(tau, 3, p)) % p)
    z = curve.power(curve.pair(g, h), alpha)
    c0 = curve.mul(g, s)
    c1 = curve.mul(curve.add(y3, root_points[0]), s)
    ell = (pads[0]-pads[3]) % p
    ca = curve.mul(h, (cores[0]+pads[0]) % p)
    cb = curve.mul(h, (2*cores[0]+pads[3]) % p)
    # The original target is created while only root 1 is installed; roots 2--4
    # are installed before the two later service plans. Core 1 is never replaced.
    public_setup = {"N": 4, "nodes": [1, 2, 3, 4], "g": encode_point(g),
                    "h": encode_point(h), "Y_3": encode_point(y3),
                    "Gamma": encode_point(gamma), "Z": gt_record(z)}
    setup_id = digest(canonical({"parameters": parameters, "published_subset": public_setup}))
    context_record = {"domain": "CHARE-A2-original-singleton-reference-context-v1",
                      "setup_id": setup_id, "target_sequence": 1,
                      "snapshot": "root-1-only-before-later-root-installation", "J": [1],
                      "policy": [], "literal_signs": [], "weights": [],
                      "root_record_ids": [digest(canonical({"core_id": "core:1", "V": encode_point(root_points[0])}))],
                      "C0": encode_point(c0), "C1": encode_point(c1)}
    context = canonical(context_record)
    ledger = cross_call_ledger(p, ell)
    fixture = {"schema": "CHARE-A2-cross-call-coordinate-public-v1",
               "backend": {"name": "R3 independent_pairing.Curve (reused external backend)",
                           "sha256": backend_hash},
               "parameters": parameters, "published_setup_subset": public_setup,
               "public_roots": {f"core:{i+1}": encode_point(point) for i, point in enumerate(root_points)},
               "original_ciphertext": {"C0": encode_point(c0), "C1": encode_point(c1)},
               "original_context_record": context_record,
               "original_context_hex": context.hex(), "original_target_id": digest(context),
               "visible_points": {"C_a1": encode_point(ca), "C_b1": encode_point(cb)},
               "ledger": ledger,
               "ordinary_mask_correction": "zero: both calls use the actual core-only service",
               "service_plans": {"participants": [1, 2, 3, 4], "k": 2,
                                 "call_a": {"polynomial_ascending": [1], "visible_nodes": [1]},
                                 "call_b": {"polynomial_ascending": [1, 1], "visible_nodes": [1]},
                                 "graph_edges_per_call": [[1, 2], [2, 3], [3, 4]]},
               "extra_opening_provenance": "The sampling endpoint 2 retains edge-12 pads from both calls and returns their scalar difference through an extra pad-only interface; no holder corruption is modeled.",
               "fresh_sampling": "All four cores and all six edge/call pads are independent secrets.randbelow(p) draws before the extra opening; no seed or private exponent is exported.",
               "scope": "A new A2 coordinate recovery fixture outside C5's protected-pad contract; unused public setup arrays and transport are not part of this functional replay."}
    encoded = json.dumps(fixture, sort_keys=True, indent=2)+"\n"
    arguments.fixture.write_text(encoded)
    expected_gt = curve.power(z, s)
    encoded_expected = curve.encode_gt(expected_gt)
    expected = {"schema": "CHARE-A2-cross-call-coordinate-expected-v1",
                "fixture_sha256": digest(encoded.encode()),
                "expected_gt_sha256": digest(encoded_expected),
                "expected_reference_kdf_digest": reference_kdf(context, encoded_expected),
                "method": "Computed in the separate producer process as Z^s from the original encapsulation; only hashes are exported. No truth value is passed to recover_public()."}
    arguments.expected.write_text(json.dumps(expected, sort_keys=True, indent=2)+"\n")
    print(json.dumps({"stage": "generate", "status": "PASS", "backend_reused": True,
                      "private_scalar_files_written": 0,
                      "fixture_sha256": expected["fixture_sha256"],
                      "elapsed_seconds": round(time.monotonic()-started, 3)}))


def recover_public(module, fixture, actual_backend_hash):
    """Only public fixture data enters this function; no expected file path."""
    assert actual_backend_hash == fixture["backend"]["sha256"]
    curve = module.Curve(fixture["parameters"])
    context_record = fixture["original_context_record"]
    context = bytes.fromhex(fixture["original_context_hex"])
    assert canonical(context_record) == context and digest(context) == fixture["original_target_id"]
    ciphertext = fixture["original_ciphertext"]
    assert context_record["C0"] == ciphertext["C0"] and context_record["C1"] == ciphertext["C1"]
    assert context_record["J"] == [1] and context_record["policy"] == []
    setup = fixture["published_setup_subset"]
    assert fixture["ordinary_mask_correction"].startswith("zero:")
    all_points = [decode_point(setup[name]) for name in ("g", "h", "Y_3", "Gamma")]
    all_points += [decode_point(x) for x in fixture["public_roots"].values()]
    all_points += [decode_point(x) for x in fixture["visible_points"].values()]
    all_points += [decode_point(x) for x in ciphertext.values()]
    assert all(curve.valid(point) for point in all_points)
    ledger = fixture["ledger"]
    assert ledger["field_prime"] == curve.p
    assert ledger["mask_mode"] == "core_only"
    certificate = inspect_ledger(ledger)
    verify_certificate(ledger, certificate)
    assert [x["core_direction"] for x in certificate["basis"]] == [[1, 0, 0, 0]]
    h, gamma = decode_point(setup["h"]), decode_point(setup["Gamma"])
    recovered_point = None
    for operation in certificate["basis"][0]["operation_recipe"]:
        coefficient = signed(operation["coefficient_mod_p"], curve.p)
        if operation["kind"] == "contribution":
            point = decode_point(fixture["visible_points"][operation["handle"]])
        elif operation["kind"] == "pad_scalar_times_h":
            point = curve.mul(h, operation["actual_scalar_mod_p"])
        else:
            raise AssertionError("this fixture uses scalar observations only")
        recovered_point = curve.add(recovered_point, curve.mul(point, coefficient))
    q = curve.mul(h, -1)
    r = curve.add(gamma, recovered_point)
    c0, c1 = decode_point(ciphertext["C0"]), decode_point(ciphertext["C1"])
    first, second = curve.pair(c0, r), curve.pair(c1, q)
    recovered_gt = curve.fm(first, second)
    encoded_gt = curve.encode_gt(recovered_gt)
    # Negative control: changing the actual affine answer by +1 changes R by h.
    wrong_answer_gt = curve.fm(curve.pair(c0, curve.add(r, h)), second)
    wrong_context = context + b"-different-context"
    return {"curve": curve, "certificate": certificate,
            "recovered_core_point": encode_point(recovered_point),
            "recovered_gt_sha256": digest(encoded_gt),
            "recovered_reference_kdf_digest": reference_kdf(context, encoded_gt),
            "wrong_pad_answer_gt_sha256": digest(curve.encode_gt(wrong_answer_gt)),
            "wrong_context_reference_kdf_digest": reference_kdf(wrong_context, encoded_gt),
            "zero_randomizer_from_public_C0": c0 is None,
            "validated_public_curve_points": len(all_points)}


def replay(arguments):
    started = time.monotonic()
    module, backend_hash = load_backend(arguments.backend)
    encoded_fixture = arguments.fixture.read_bytes()
    fixture = json.loads(encoded_fixture)
    recovered = recover_public(module, fixture, backend_hash)
    # Expected digests are deliberately opened only after public recovery ends.
    expected = json.loads(arguments.expected.read_text())
    assert digest(encoded_fixture) == expected["fixture_sha256"]
    assert recovered["recovered_gt_sha256"] == expected["expected_gt_sha256"]
    assert recovered["recovered_reference_kdf_digest"] == expected["expected_reference_kdf_digest"]
    negative_status = wrong_pad_answer_control(recovered["zero_randomizer_from_public_C0"],
                         recovered["recovered_gt_sha256"], recovered["wrong_pad_answer_gt_sha256"])
    assert recovered["wrong_context_reference_kdf_digest"] != expected["expected_reference_kdf_digest"]
    curve = recovered.pop("curve")
    result = {"schema": "CHARE-A2-cross-call-coordinate-results-v1", "status": "PASS",
              "new_A2_coordinate_fixtures": 1, "old_R3_fixtures_rerun": 0,
              "backend_reused": fixture["backend"], "p_bits": curve.p.bit_length(),
              "q_bits": curve.q.bit_length(), "pairing_calls_during_replay": curve.pairing_count,
              "full_Miller_vertical_terms_during_replay": curve.vertical_count,
              "expected_file_read_after_recovery": True,
              "no_private_scalar_or_seed_in_replay_input": True,
              "ordinary_mask_correction": fixture["ordinary_mask_correction"],
              "original_ciphertext_and_context_reused": True,
              "wrong_pad_answer_rejected": negative_status == "PASS",
              "wrong_pad_answer_control_status": negative_status,
              "wrong_context_digest_differs": True,
              "fixture_sha256": expected["fixture_sha256"],
              "elapsed_seconds": round(time.monotonic()-started, 3),
              "scope": "Python affine-curve functional cross-check only; no native Go/PBC, authenticated transport, performance, or security-level claim",
              **recovered}
    arguments.output.write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    print(json.dumps({key: result[key] for key in ("status", "new_A2_coordinate_fixtures", "p_bits", "q_bits",
                      "pairing_calls_during_replay", "wrong_pad_answer_rejected", "elapsed_seconds")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "replay"))
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--parameters", type=Path)
    parser.add_argument("--fixture", type=Path, default=Path(__file__).with_name("cross_call_curve_public.json"))
    parser.add_argument("--expected", type=Path, default=Path(__file__).with_name("cross_call_curve_expected.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("cross_call_curve_results.json"))
    arguments = parser.parse_args()
    if arguments.command == "generate":
        if arguments.parameters is None:
            parser.error("generate requires --parameters")
        generate(arguments)
    else:
        replay(arguments)


if __name__ == "__main__":
    main()
