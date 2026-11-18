#!/usr/bin/env python3
"""New A2 tests only; finite-field identities, not a native security experiment."""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import random
from pathlib import Path

from joint_pad_reference import inspect_ledger, row_basis, verify_certificate


def dot(a, b, p):
    return sum(x * y for x, y in zip(a, b)) % p


def cross_call_ledger(p=101, actual_difference=71):
    core_ids = [f"core:{i}" for i in range(1, 5)]
    pad_ids = [f"call:{call}/edge:{edge}" for call in ("a", "b")
               for edge in ("12", "23", "34")]
    contributions = []
    for call, weights in (("a", [1]*4), ("b", [2, 3, 4, 5])):
        block = 0 if call == "a" else 3
        for i in range(4):
            a, b = [0]*4, [0]*6
            a[i] = weights[i]
            if i < 3:
                b[block+i] = 1
            if i > 0:
                b[block+i-1] = -1
            contributions.append({"id": f"call:{call}/node:{i+1}",
                                  "handle": f"C_{call}{i+1}",
                                  "visible": i == 0, "a": a, "b": b})
    return {"schema": "CHARE-A2-pad-only-ledger-v1", "field_prime": p,
            "observation_scope": "pad_only_linear", "mask_mode": "core_only", "core_ids": core_ids,
            "pad_ids": pad_ids, "contributions": contributions,
            "aliases": {"replay:call:a/node:1": "call:a/node:1"},
            "pad_observations": [{"id": "opening:cross-call-difference",
                                  "source_family": "pad_only",
                                  "row": [1, 0, 0, -1, 0, 0],
                                  "representation": {"kind": "scalar", "handle": "ell",
                                                     "value": actual_difference % p}}]}


def direct_span(rows, p, width):
    # Exhaustive independent oracle. No elimination or reference-engine helper.
    return {tuple(sum(c*row[j] for c, row in zip(coefficients, rows)) % p
                  for j in range(width))
            for coefficients in itertools.product(range(p), repeat=len(rows))}


def brute_pure_core(ledger):
    p = ledger["field_prime"]
    n, q = len(ledger["core_ids"]), len(ledger["pad_ids"])
    rows = [x["a"] + x["b"] for x in ledger["contributions"] if x["visible"]]
    rows += [[0]*n + x["row"] for x in ledger.get("pad_observations", [])]
    return {u[:n] for u in direct_span(rows, p, n+q) if not any(u[n:])}


def graph_components(n, edges, exposed, visible, weights):
    # Independent graph oracle. No matrix or nullspace computation.
    adjacency = [set() for _ in range(n)]
    for e, (i, j) in enumerate(edges):
        if e not in exposed:
            adjacency[i].add(j)
            adjacency[j].add(i)
    unseen, answer = set(range(n)), []
    while unseen:
        root = next(iter(unseen))
        stack, component = [root], set()
        while stack:
            i = stack.pop()
            if i not in component:
                component.add(i)
                stack.extend(adjacency[i] - component)
        unseen -= component
        if component <= visible:
            answer.append([weights[i] if i in component else 0 for i in range(n)])
    return answer


def graph_ledger(p, n, edges, exposed, visible, weights):
    rows = []
    for i in range(n):
        a = [0]*n
        a[i] = weights[i]
        b = [int(i == u)-int(i == v) for u, v in edges]
        rows.append({"id": f"contribution:{i}", "handle": f"C_{i}",
                     "visible": i in visible, "a": a, "b": b})
    openings = []
    for e in sorted(exposed):
        vector = [int(j == e) for j in range(len(edges))]
        openings.append({"id": f"open:{e}", "row": vector,
                         "representation": {"kind": "h_point", "handle": f"r_{e}h"}})
    return {"field_prime": p, "mask_mode": "core_only", "core_ids": [f"core:{i}" for i in range(n)],
            "pad_ids": [f"pad:{e}" for e in range(len(edges))],
            "contributions": rows, "pad_observations": openings}


def directions(result):
    return [x["core_direction"] for x in result["basis"]]


def evaluate_operations(ledger, certificate, cores, pads):
    p = ledger["field_prime"]
    contributions = {x["id"]: x for x in ledger["contributions"]}
    observations = {x["id"]: x for x in ledger.get("pad_observations", [])}
    result = 0
    for operation in certificate["operation_recipe"]:
        if operation["kind"] == "contribution":
            source = contributions[operation["source_id"]]
            assert source["visible"]
            value = dot(source["a"], cores, p) + dot(source["b"], pads, p)
        else:
            source = observations[operation["source_id"]]
            value = dot(source["row"], pads, p)
            if source["representation"]["kind"] == "scalar":
                assert value == source["representation"]["value"] % p
                assert value == operation["actual_scalar_mod_p"]
        result += operation["coefficient_mod_p"] * value
    return result % p


def run_tests():
    rng = random.Random(20261110)  # Public algebra-test seed only; no curve fixture uses it.
    counts = {}
    cross = cross_call_ledger()
    result = inspect_ledger(cross)
    verify_certificate(cross, result)
    assert directions(result) == [[1, 0, 0, 0]]
    item = result["basis"][0]
    assert item["contribution_coefficients"] == {"call:a/node:1": 100, "call:b/node:1": 1}
    assert item["pad_observation_coefficients_d"] == {"opening:cross-call-difference": 100}
    assert evaluate_operations(cross, item, [9, 14, 27, 41], [17, 23, 31, 47, 53, 61]) == 9
    forged_recipe = copy.deepcopy(result)
    forged_recipe["basis"][0]["operation_recipe"][0]["coefficient_mod_p"] += 1
    try:
        verify_certificate(cross, forged_recipe)
    except ValueError:
        pass
    else:
        raise AssertionError("a changed operation recipe was not rejected")
    no_relation = copy.deepcopy(cross)
    no_relation["pad_observations"] = []
    assert inspect_ledger(no_relation)["core_capability_dimension"] == 0
    for call in ("a", "b"):
        local = copy.deepcopy(cross)
        for contribution in local["contributions"]:
            contribution["visible"] &= contribution["id"].startswith(f"call:{call}/")
        assert inspect_ledger(local)["core_capability_dimension"] == 0
    edges = [(0, 1), (1, 2), (2, 3)]
    assert graph_components(4, edges, set(), {0}, [1]*4) == []
    assert graph_components(4, edges, set(), {0}, [2, 3, 4, 5]) == []
    # Row-space intersection with either pad block is zero; projection is not disclosure.
    lspace = direct_span([[1, 0, 0, -1, 0, 0]], 101, 6)
    assert {u for u in lspace if not any(u[3:])} == {(0,)*6}
    assert {u for u in lspace if not any(u[:3])} == {(0,)*6}
    # Full joint closure also isolates the edge-12 pad points. Do not claim
    # that both graphs remain connected after this restored closure.
    ca_value, cb_value, ell_value = 26, 65, 71
    recovered_vh = (cb_value-ca_value+ell_value) % 101
    assert (ca_value-recovered_vh) % 101 == 17
    assert (cb_value-2*recovered_vh) % 101 == 47
    counts["cross_call_joint_and_separate_checks"] = 1

    samples = 0
    for p in (7, 11, 101):
        for _ in range(80):
            cores = [rng.randrange(p) for _ in range(4)]
            pads = [rng.randrange(p) for _ in range(6)]
            ledger = cross_call_ledger(p, pads[0]-pads[3])
            output = inspect_ledger(ledger)
            verify_certificate(ledger, output)
            recovered_core = evaluate_operations(ledger, output["basis"][0], cores, pads)
            assert recovered_core == cores[0]
            # Original N=4 singleton, actual setup range p>N+1, unknown theta.
            a, theta = rng.randrange(1, p), rng.randrange(1, p)
            alpha, s = rng.randrange(p), rng.randrange(p)
            tau = rng.choice([x for x in range(p) if x not in (0, 1, 2, 3, 4)])
            c0 = s
            c1 = s*(a*pow(tau, 3, p)+cores[0]) % p
            gamma = (alpha+a*pow(tau, 3, p))*theta % p
            r = (gamma + recovered_core*theta) % p
            q = -theta % p
            assert (c0*r+c1*q) % p == s*alpha*theta % p
            samples += 1
    counts["original_singleton_exponent_identity_samples"] = samples

    conditional_pairs = {}
    for ra, rb in itertools.product(range(7), repeat=2):
        conditional_pairs.setdefault((ra-rb) % 7, []).append((ra, rb))
    for ell, pairs in conditional_pairs.items():
        assert len(pairs) == 7
        assert sorted(ra for ra, _ in pairs) == list(range(7))
        assert sorted(rb for _, rb in pairs) == list(range(7))
        assert set(pairs) == {((z+ell) % 7, z) for z in range(7)}
    counts["conditional_pad_samples"] = 49

    graph_count = 0
    graphs = [(1, []), (2, [(0, 1)]), (3, [(0, 1), (1, 2)]),
              (3, [(0, 1), (1, 2), (2, 0)]),
              (4, [(0, 1), (1, 2), (2, 3)]),
              (4, [(0, 1), (1, 2), (2, 3), (3, 0)])]
    for n, edges in graphs:
        for opening_bits in itertools.product((0, 1), repeat=len(edges)):
            exposed = {i for i, x in enumerate(opening_bits) if x}
            for visible_bits in itertools.product((0, 1), repeat=n):
                visible = {i for i, x in enumerate(visible_bits) if x}
                for weights in ([1]*n, list(range(2, n+2)), [0]*n):
                    ledger = graph_ledger(7, n, edges, exposed, visible, weights)
                    output = inspect_ledger(ledger)
                    verify_certificate(ledger, output)
                    expected = graph_components(n, edges, exposed, visible, weights)
                    assert row_basis(expected, 7, n) == directions(output)
                    graph_count += 1
    counts["targeted_coordinate_component_cases"] = graph_count

    joint_cases = 0
    for _ in range(64):
        ledger = cross_call_ledger(7, 0)
        ledger["pad_observations"] = []
        expected = []
        for call, weights, offset in (("a", [1]*4, 0), ("b", [2, 3, 4, 5], 3)):
            visible = {i for i in range(4) if rng.randrange(2)}
            exposed = {i for i in range(3) if rng.randrange(2)}
            for row in ledger["contributions"]:
                if row["id"].startswith(f"call:{call}/"):
                    row["visible"] = int(row["id"].rsplit(":", 1)[1])-1 in visible
            for edge in exposed:
                ledger["pad_observations"].append({"id": f"open:{call}:{edge}",
                    "row": [int(j == offset+edge) for j in range(6)],
                    "representation": {"kind": "h_point", "handle": f"r_{call}_{edge}h"}})
            expected += graph_components(4, [(0,1), (1,2), (2,3)], exposed, visible, weights)
        output = inspect_ledger(ledger)
        verify_certificate(ledger, output)
        assert directions(output) == row_basis(expected, 7, 4)
        joint_cases += 1
    counts["joint_coordinate_block_cases"] = joint_cases

    brute_count = 0
    for case in range(50):
        p, n, q = (3 if case % 2 else 5), 2, rng.randrange(3)
        m, ell = rng.randrange(4), rng.randrange(3)
        ledger = {"field_prime": p, "mask_mode": "core_only", "core_ids": ["core:0", "core:1"],
                  "pad_ids": [f"pad:{j}" for j in range(q)], "contributions": [],
                  "pad_observations": []}
        for j in range(m):
            ledger["contributions"].append({"id": f"c:{j}", "handle": f"C{j}",
                "visible": bool(rng.randrange(2)), "a": [rng.randrange(p) for _ in range(n)],
                "b": [rng.randrange(p) for _ in range(q)]})
        for j in range(ell):
            ledger["pad_observations"].append({"id": f"l:{j}",
                "row": [rng.randrange(p) for _ in range(q)],
                "representation": {"kind": "h_point", "handle": f"O{j}"}})
        output = inspect_ledger(ledger)
        verify_certificate(ledger, output)
        assert direct_span(directions(output), p, n) == brute_pure_core(ledger)
        brute_count += 1
    counts["independent_exhaustive_linear_span_oracles"] = brute_count

    # Dependent rows preserve capability; aliases do not mint fresh sources.
    dependent = copy.deepcopy(cross)
    duplicate = copy.deepcopy(dependent["pad_observations"][0])
    duplicate["id"] = "dependent:opening"
    duplicate["row"] = [2*x for x in duplicate["row"]]
    duplicate["representation"] = {"kind": "scalar", "handle": "2ell", "value": 142}
    dependent["pad_observations"].append(duplicate)
    assert directions(inspect_ledger(dependent)) == directions(result)
    aliases_removed = copy.deepcopy(cross)
    aliases_removed.pop("aliases")
    assert inspect_ledger(aliases_removed) == result
    granted = copy.deepcopy(cross)
    granted["mask_mode"] = "message_game_grant"
    assert not inspect_ledger(granted)["physical_recipe_eligible"]
    assert inspect_ledger(granted)["actual_group_replay"] == "NOT_RUN"
    boundary_cases = 4
    malformed = []
    inconsistent = copy.deepcopy(dependent)
    inconsistent["pad_observations"][-1]["representation"]["value"] += 1
    malformed.append(inconsistent)
    for scope in ("mixed_sources", "nonlinear"):
        bad = copy.deepcopy(cross)
        bad["observation_scope"] = scope
        malformed.append(bad)
    missing_scalar = copy.deepcopy(cross)
    del missing_scalar["pad_observations"][0]["representation"]["value"]
    malformed.append(missing_scalar)
    duplicate_id = copy.deepcopy(cross)
    duplicate_id["contributions"].append(copy.deepcopy(duplicate_id["contributions"][0]))
    malformed.append(duplicate_id)
    missing_mode = copy.deepcopy(cross)
    del missing_mode["mask_mode"]
    malformed.append(missing_mode)
    unrepresented_correction = copy.deepcopy(cross)
    unrepresented_correction["mask_mode"] = "corrected_actual"
    malformed.append(unrepresented_correction)
    for bad in malformed:
        try:
            inspect_ledger(bad)
        except ValueError:
            boundary_cases += 1
        else:
            raise AssertionError("malformed ledger was accepted")
    counts["representation_and_scope_boundary_cases"] = boundary_cases
    return {"schema": "CHARE-A2-pad-regression-results-v1", "status": "PASS",
            "new_A2_counts": counts,
            "scope": "Independent stdlib exact-linear reference; finite tests support the proof, not security claims",
            "original_A1_suite_rerun": False,
            "cross_call_before_relation_dimension": 0,
            "cross_call_after_relation_dimension": 1,
            "cross_call_recovered_original_core_direction": [1, 0, 0, 0],
            "joint_closure_also_isolates_both_edge_12_pad_points": True,
            "C5_contract": "Unchanged; the extra cross-call pad relation is outside protected internal pads",
            "cross_call_certificate": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("joint_pad_results.json"))
    parser.add_argument("--fixture", type=Path, default=Path(__file__).with_name("cross_call_ledger.json"))
    args = parser.parse_args()
    result = run_tests()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    args.fixture.write_text(json.dumps(cross_call_ledger(), ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "new_A2_counts": result["new_A2_counts"]}))


if __name__ == "__main__":
    main()
