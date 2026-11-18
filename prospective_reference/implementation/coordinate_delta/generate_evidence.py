"""Generate new actual-coordinate evidence for the pending-pad-opening guard.

This is a fresh adapter/experiment. It reuses, but does not redistribute, the
prior coordinate-only backend. Secret fixture scalars are sampled in memory
with secrets.randbelow and are not written. Saved public fixtures support an
exact, isolated replay. Regeneration produces new coordinates, same checks.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import secrets
import sys

from public_replay import canonical, kdf, load_backend, sha

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "implementation"))
from controller.controller import (Controller, SourceRecord, Envelope, PadEdge,
                                   Plan, CanonicalTarget)


def must(decision, operation):
    if not decision.accepted:
        raise AssertionError((operation, decision.to_dict()))
    return decision.to_dict()


def make_fixture(b, fixture_id):
    p, n = b.p, 4
    rnd = lambda: secrets.randbelow(p)
    nonzero = lambda: secrets.randbelow(p - 1) + 1
    g = b.generator()
    a, alpha, theta = nonzero(), rnd(), nonzero()
    tau = nonzero()
    while tau in (1, 2, 3, 4):
        tau = nonzero()
    h = b.mul(g, theta)
    gamma = b.mul(h, (alpha + a * pow(tau, n - 1, p)) % p)
    y = [b.mul(g, a * pow(tau, d, p) % p) for d in range(n)]
    t = [b.mul(h, pow(tau, d, p)) for d in range(n)]
    z = b.fpow(b.pair(g, h), alpha)
    values = [rnd() for _ in range(n)]
    roots = [b.mul(g, v) for v in values]
    projections = [[b.mul(b.add(t[k + 1], b.neg(b.mul(t[k], i + 1))), values[i])
                    for k in range(n - 1)] for i in range(n)]
    projection_checks = 0
    for i in range(n):
        for k in range(n - 1):
            left = b.pair(roots[i], b.add(t[k + 1], b.neg(b.mul(t[k], i + 1))))
            right = b.pair(g, projections[i][k])
            if left != right:
                raise AssertionError("Public source projection validation failed")
            projection_checks += 1

    public = {"g": b.public_point(g), "h": b.public_point(h),
              "Gamma": b.public_point(gamma), "Y": [b.public_point(x) for x in y],
              "T": [b.public_point(x) for x in t], "Z": b.public_gt(z),
              "roots": [{"source_id": "v" + str(i + 1), "node": i + 1,
                         "V": b.public_point(roots[i]),
                         "projections": [b.public_point(x) for x in projections[i]]}
                        for i in range(n)]}
    # The old snapshot contains only root 1. The later controller imports that
    # immutable public target after the other three root records are installed.
    # Use a nonzero valid encapsulation exponent so the negative controls do
    # not exercise the allowed but degenerate s=0 event.
    s = nonzero()
    c0 = b.mul(g, s)
    c1 = b.mul(b.add(y[n - 1], roots[0]), s)
    context = {"setup_id": sha(canonical({k: public[k] for k in ("g", "h", "Gamma", "Y", "T", "Z")})),
               "instance_id": fixture_id, "snapshot_id": "original-root-1-only",
               "source_ids": ["v1"], "policy": [], "weights": [], "J": [1],
               "root_record_digest": sha(canonical(public["roots"][0])),
               "C0": b.public_point(c0), "C1": b.public_point(c1)}
    target = {"target_id": fixture_id + "/old-singleton",
              "C0": b.public_point(c0), "C1": b.public_point(c1),
              "original_context": context}
    expected_gt = b.fpow(z, s)
    expected_key = kdf(b, canonical(context), expected_gt)
    expected = {"fixture_id": fixture_id,
                "target_element_sha256": sha(b.encode_gt(expected_gt)),
                "key_sha256": sha(expected_key),
                "context_sha256": sha(canonical(context)),
                "isolated_core_point_sha256": sha(b.encode_point(b.mul(h, values[0])))}

    sources = [SourceRecord("v" + str(i + 1), "core", "owner" + str(i + 1),
                            "root" + str(i + 1), i + 1, "core-generation-" + str(i + 1),
                            None, "canonical_core_v1", "public-root-" + str(i + 1))
               for i in range(n)]
    manifest = {"receipt-" + x.source_id: asdict(x) for x in sources}
    def verifier(descriptor, receipt):
        return manifest.get(receipt) == descriptor
    ctl = Controller(p, (1, 2, 3, 4), [(x, "receipt-" + x.source_id) for x in sources],
                     Envelope(2), verifier, prime_is_prevalidated=True)
    target_ref = CanonicalTarget(target["target_id"], ("v1",),
                                 sha(canonical(target)), sha(canonical(context)))
    must(ctl.admit_target(target_ref, ctl.revision, lambda: "retained-target/" + fixture_id),
         "import original target before service history")
    edges = tuple(PadEdge("p" + str(i) + str(i + 1), "v" + str(i), "v" + str(i + 1),
                          fixture_id + "/private-delivery/" + str(i)) for i in (1, 2, 3))
    plan = Plan(fixture_id + "/plan", fixture_id + "/invocation", "constant", 0,
                tuple(x.source_id for x in sources), (1,), edges)
    freeze = must(ctl.freeze_plan(plan, ctl.revision), "freeze full possible-row plan")
    pads = {}
    def install():
        for edge in edges:
            pads[edge.pad_id] = rnd()
        return "private-pad-deliveries-installed/" + fixture_id
    must(ctl.install_pads(plan.plan_id, ctl.revision, install), "install only after approval")
    before_count = ctl.callback_count
    denied_callback_count = [0]
    def denied_emitter():
        denied_callback_count[0] += 1
        return "must-never-be-published"
    denied = ctl.request_pad_opening("open-p12", {"p12": 1}, ctl.revision, denied_emitter)
    if denied.accepted or denied.private_callback_called or denied_callback_count[0] != 0:
        raise AssertionError("Dangerous pad opening was not rejected before the callback")
    if ctl.callback_count != before_count:
        raise AssertionError("Private callback count changed after rejection")
    visible_before = ctl.capability(potential=False)
    if visible_before:
        raise AssertionError("No contribution was visible at the rejected opening")

    # Safe branch: the original plan can still finish without the denied opening.
    emitted_points = {}
    for i, source in enumerate(sources):
        def emit(i=i, source=source):
            v = values[i]
            for edge in edges:
                if edge.tail == source.source_id:
                    v += pads[edge.pad_id]
                elif edge.head == source.source_id:
                    v -= pads[edge.pad_id]
            point = b.mul(h, v % p)
            emitted_points[source.source_id] = point
            return "contribution/" + sha(b.encode_point(point))
        must(ctl.emit_contribution(plan.plan_id, source.source_id, ctl.revision, emit),
             "complete protected-pad plan")
    full_sum = b.sum_points(emitted_points.values())
    verified_sum = b.pair(g, full_sum) == b.pair(b.sum_points(roots), h)
    if not verified_sum:
        raise AssertionError("Service output verification relation failed")

    # Deliberately bypass the guard in a separate public branch: first reveal
    # r12*h, then reveal node 1's planned contribution. No scalar is exported.
    opening = {"pad_id": "p12", "point": b.public_point(b.mul(h, pads["p12"]))}
    first = {"source_id": "v1", "plan_id": plan.plan_id,
             "point": b.public_point(emitted_points["v1"])}
    fixture = {"fixture_id": fixture_id, "public": public, "target": target,
               "opening": opening, "first_contribution": first,
               "negative_control_opening": {"pad_id": "public-offset-of-p12", "point": b.public_point(b.mul(h, (pads["p12"] + 1) % p))},
               "declared_fixture_order": ["publish root 1", "publish original singleton target",
                                      "publish roots 2,3,4", "freeze full plan",
                                      "install private pads", "bypass guard and open p12",
                                      "publish first planned contribution"],
               "note": "Logical fixture history; the controller imports the retained root-1-only target after initialization. Actual guard/callback order is in guard_trace. The negative control is the public offset r12*h+h, not another secret pad opening."}
    verification = {"fixture_id": fixture_id, "status": "PASS", "p_bits": p.bit_length(),
                    "q_bits": b.q.bit_length(), "projection_equations_checked": projection_checks,
                    "trusted_binding": "explicit fixture manifest, not a signature implementation",
                    "freeze": freeze, "rejected_opening": denied.to_dict(),
                    "rejected_private_callback_count": denied_callback_count[0],
                    "current_capability_rank_at_proposal": len(visible_before),
                    "safe_branch_final_current_rank": len(ctl.capability(potential=False)),
                    "safe_branch_full_sum_pairing_relation": verified_sum,
                    "guard_trace": ctl.trace,
                    "secret_fixture_scalars_persisted": False}
    return fixture, expected, verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-dir", required=True)
    parser.add_argument("--manifest", default=str(ROOT / "DEPENDENCIES.json"))
    parser.add_argument("--output-dir", default=str(ROOT / "evidence"))
    parser.add_argument("--fixtures", type=int, default=2)
    args = parser.parse_args()
    if args.fixtures < 1:
        parser.error("--fixtures must be positive")
    b = load_backend(args.backend_dir, json.loads(Path(args.manifest).read_text()))
    fixtures, expected, results = [], [], []
    for i in range(args.fixtures):
        f, e, r = make_fixture(b, "pending-opening-" + str(i + 1))
        fixtures.append(f); expected.append(e); results.append(r)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    values = {"coordinate_public_inputs.json": {"schema": "chare.pending-opening.public-inputs.v1", "fixtures": fixtures},
              "coordinate_expected_hashes.json": {"schema": "chare.pending-opening.expected.v1", "expected": expected},
              "coordinate_guard_results.json": {"schema": "chare.pending-opening.guard.v1", "results": results}}
    for name, data in values.items():
        (out / name).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "fixtures": len(results),
                      "projection_equations": sum(x["projection_equations_checked"] for x in results),
                      "dangerous_opening_callbacks": sum(x["rejected_private_callback_count"] for x in results)}))


if __name__ == "__main__":
    main()
