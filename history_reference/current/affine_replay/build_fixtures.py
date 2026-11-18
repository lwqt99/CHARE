#!/usr/bin/env python3
"""Private fixture generation, deliberately separate from the recovery module.

The source assignments and encapsulation scalar below are consumed only here.
Public fixtures and expected encapsulator outputs are written to separate files.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from affine_replay import curve, prior, R

HERE = Path(__file__).resolve().parent


def expr(terms, constant=0):
    return {"visibility": "observer", "constant": constant % R, "terms": terms}


def build(name, N, nodes, source_values, target_rows, constants,
          numerical_rows=(), point_rows=(), aliases=(), eta=None):
    pp, setup_private = prior.setup(N)
    h, g = prior.point(pp["h"]), prior.point(pp["g"])
    tau, beta = setup_private["tau"], setup_private["beta"]
    # Vary the encapsulator input across fixtures; expected GT values must not
    # all be one shared constant. This value never enters the public API.
    encapsulation_scalar = 1+int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big") % (R-1)
    sources = list(source_values)
    alias_map = dict(aliases)

    def resolve(name):
        seen = set()
        while name in alias_map:
            if name in seen:
                raise ValueError("Fixture alias cycle")
            seen.add(name)
            name = alias_map[name]
        return name

    def value(terms, constant=0):
        return (constant+sum(coefficient*source_values[resolve(source)]
                             for source, coefficient in terms.items())) % R

    eta = [0]*len(nodes) if eta is None else list(eta)
    X, projections, F = [], [], []
    for node, row, constant, residual in zip(nodes, target_rows, constants, eta):
        ordinary = value(row, constant)
        exponent = (ordinary+residual*beta*pow(tau-node, -1, R)) % R
        X.append(prior.point_hex(curve.mul(exponent, g)))
        ladder = []
        for k in range(N-1):
            base = curve.linear_combination([(1, prior.point(pp["T"][k+1])),
                                             (-node, prior.point(pp["T"][k]))])
            p = curve.linear_combination([(ordinary, base),
                                         (residual, prior.point(pp["B"][k]))])
            ladder.append(prior.point_hex(p))
        projections.append(ladder)
        F.append([row.get(source, 0) % R for source in sources])
    aggregate = curve.linear_combination(
        [(1, prior.point(pp["Y"][N-len(nodes)]))]+[(1, prior.point(point)) for point in X])
    C0 = prior.point_hex(curve.mul(encapsulation_scalar, g))
    C1 = prior.point_hex(curve.mul(encapsulation_scalar, aggregate))
    model = {"source_ids": sources, "F_columns": F, "c": list(constants), "eta": eta,
             "affine_descriptor_visibility": "observer", "residual_visibility": "observer"}
    binding = {"instance": name, "setup_id": pp["setup_id"],
               "snapshot": "original-before-affine-disclosures",
               "record_ids": ["original-record-"+str(node) for node in nodes],
               "nodes": list(nodes), "X": X, "projections": projections,
               "C0": C0, "C1": C1, "affine_source_model": copy.deepcopy(model)}
    target = {"setup_id": pp["setup_id"], "nodes": list(nodes), "X": X,
              "projections": projections, "C0": C0, "C1": C1, **model,
              "context_object": binding, "context_hex": prior.canonical_json(binding).hex()}
    equations = [{"equation_id": "visible-equation-"+str(i), "visibility": "observer",
                  "evidence_id": "fixture-observed-numerical-answer-"+str(i),
                  "terms": row, "rhs": value(row)}
                 for i, row in enumerate(numerical_rows)]
    points = [{"handle_id": "visible-point-"+str(i), "visibility": "observer",
               "point": prior.point_hex(curve.mul(value(row, constant), h)),
               "expression": expr(row, constant),
               "recipe": {"kind": "visible_point_handle",
                          "observation_id": "fixture-observed-point-"+str(i)}}
              for i, (row, constant) in enumerate(point_rows)]
    ledger = {"schema": "CHARE-observer-affine-ledger-v1", "source_ids": sources,
              "aliases": [{"alias": alias, "canonical_source_id": destination,
                           "visibility": "observer", "evidence_id": "explicit-physical-source-alias"}
                          for alias, destination in aliases],
              "equations": equations, "points": points}
    recovered_gt = curve.decode_gt(bytes.fromhex(pp["Z"]))**encapsulation_scalar
    fixture = {"schema": "CHARE-affine-public-fixture-v1", "name": name,
               "public_setup": pp, "original_target": target, "observer_ledger": ledger,
               "scope": "Actual order-131 curve points and pairings; diagnostic only, not native PBC."}
    expected = {"name": name, "GT_hex": recovered_gt.encode().hex(),
                "key_sha256": prior.key_derive(bytes.fromhex(target["context_hex"]), recovered_gt)}
    return fixture, expected


def make_all():
    fixtures = [
        build("known_numerical_core", 2, [1], {"v1": 4, "v2": 13},
              [{"v1": 1}], [5], numerical_rows=[{"v1": 1}]),
        build("numerical_core_linear_sum", 2, [1, 2], {"v1": 4, "v2": 13},
              [{"v1": 1}, {"v2": 1}], [7, 12], numerical_rows=[{"v1": 1, "v2": 2}]),
        build("known_point_affine_offset", 2, [1], {"v1": 4, "v2": 13},
              [{"v1": 1}], [5], point_rows=[({"v1": 1}, 17)]),
        build("mixed_masks_with_actual_rhs", 2, [1, 2],
              {"v1": 4, "v2": 13, "mask1": 31, "mask2": 47},
              [{"v1": 1, "mask1": 3}, {"v2": 1, "mask2": 3}], [3, 11],
              numerical_rows=[{"v1": 1, "v2": 2}],
              point_rows=[({"mask1": 1, "mask2": 2}, 7)]),
        build("numerical_pad_point_cancellation", 2, [1, 2],
              {"v1": 4, "v2": 13, "pad": 23},
              [{"v1": 1}, {"v2": 1}], [7, 12],
              numerical_rows=[{"v1": 1, "v2": 2, "pad": 1}],
              point_rows=[({"pad": 1}, 6)]),
        build("aliased_source_affine_sums", 3, [1, 2], {"v1": 4, "v2": 13, "shared": 22},
              [{"v1": 1}, {"v2": 1}], [9, 2],
              point_rows=[({"v1": 1, "shared-A": 1}, 17),
                          ({"v2": 1, "shared-B": 1}, 6)],
              aliases=[("shared-A", "shared"), ("shared-B", "shared")]),
        build("three_slot_affine_residual", 4, [1, 2, 4],
              {"v1": 4, "v2": 13, "v4": 51},
              [{"v1": 1}, {"v2": 1}, {"v4": 1}], [5, 9, 12], eta=[1, 0, 0],
              point_rows=[({"v2": 1}, 7), ({"v4": 1}, 3)]),
        build("opened_offset_actual_rhs", 2, [1], {"v1": 4, "offset": 17},
              [{"v1": 1}], [5], numerical_rows=[{"offset": 1}],
              point_rows=[({"v1": 1, "offset": 1}, 0)]),
    ]
    # An unknown offset remains a source coordinate in the observer model.
    # Its private realization is used only to generate the observed point.
    private_offset = build("private_offset_unopened", 2, [1], {"v1": 4, "offset": 17},
                           [{"v1": 1}], [5],
                           point_rows=[({"v1": 1, "offset": 1}, 0)])
    return fixtures, private_offset


def write_all(directory=HERE):
    positives, negative = make_all()
    (directory/"fixtures").mkdir(exist_ok=True, parents=True)
    (directory/"expected").mkdir(exist_ok=True, parents=True)
    for fixture, expected in positives+[negative]:
        (directory/"fixtures"/(fixture["name"]+".json")).write_text(
            json.dumps(fixture, indent=2, sort_keys=True)+"\n")
        (directory/"expected"/(fixture["name"]+".json")).write_text(
            json.dumps(expected, indent=2, sort_keys=True)+"\n")
    manifest = {"schema": "CHARE-affine-fixtures-manifest-v1",
                "positive_cases": [fixture["name"] for fixture, _ in positives],
                "unopened_offset_negative": negative[0]["name"]}
    (directory/"fixtures"/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE)
    args = parser.parse_args()
    print(json.dumps(write_all(args.output), indent=2))
