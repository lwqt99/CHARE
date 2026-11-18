#!/usr/bin/env python3
"""Observer-only affine witness compiler and tiny-curve replay.

This module imports the previous increment's hash-pinned curve implementation.
It does not import a fixture generator. Its public API receives neither source
assignments, setup trapdoors, an encapsulation scalar, nor expected GT/key data.
The declared point descriptors and numerical answers are provenance assumptions;
this diagnostic does not implement authentication of those statements.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prior_runtime import load_pairing, load_replay

curve = load_pairing()
prior = load_replay()
R = curve.R
H_HANDLE = "public-setup-h"


def digest(value):
    return hashlib.sha256(prior.canonical_json(value)).hexdigest()


def scalar(value):
    if type(value) is not int:
        raise ValueError("A field coefficient must be an integer")
    return value % R


def dot(left, right):
    if len(left) != len(right):
        raise ValueError("Vector widths differ")
    return sum(a*b for a, b in zip(left, right)) % R


def observer_only(record, field="visibility"):
    if record.get(field) != "observer":
        raise ValueError("An auditor-only value or descriptor is not an observer input")


def source_resolver(ledger):
    names = ledger["source_ids"]
    if not names or any(not isinstance(n, str) or not n for n in names):
        raise ValueError("Source IDs must be nonempty strings")
    if len(names) != len(set(names)):
        raise ValueError("Physical source IDs must be unique")
    links = {}
    for item in ledger["aliases"]:
        observer_only(item)
        alias, destination = item["alias"], item["canonical_source_id"]
        if alias in names or alias in links or not item.get("evidence_id"):
            raise ValueError("Alias declaration is duplicate, ambiguous, or lacks provenance")
        links[alias] = destination

    def resolve(name):
        visited = set()
        while name in links:
            if name in visited:
                raise ValueError("Alias cycle")
            visited.add(name)
            name = links[name]
        if name not in names:
            raise ValueError("Undeclared physical source: " + str(name))
        return names.index(name)

    # Validate declarations even when a particular target does not use them.
    for alias in links:
        resolve(alias)
    return names, resolve


def expression_row(expression, names, resolve):
    observer_only(expression)
    row = [0]*len(names)
    for name, coefficient in expression["terms"].items():
        index = resolve(name)
        row[index] = (row[index]+scalar(coefficient)) % R
    return scalar(expression["constant"]), row


def affine_fiber(matrix, rhs, width):
    """Compute z = particular + basis*u from the actual visible RHS.

    The free coordinates are actual original source coordinates, not newly
    sampled values. Their values are never needed by the compiler or replay.
    """
    if len(matrix) != len(rhs) or any(len(row) != width for row in matrix):
        raise ValueError("Affine equation dimensions differ")
    rows = [[scalar(x) for x in row]+[scalar(b)] for row, b in zip(matrix, rhs)]
    at, pivots = 0, []
    for column in range(width):
        pivot = next((i for i in range(at, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[at], rows[pivot] = rows[pivot], rows[at]
        scale = pow(rows[at][column], -1, R)
        rows[at] = [value*scale % R for value in rows[at]]
        for i in range(len(rows)):
            if i != at and rows[i][column]:
                scale = rows[i][column]
                rows[i] = [(a-scale*b) % R for a, b in zip(rows[i], rows[at])]
        pivots.append(column)
        at += 1
    if any(not any(row[:width]) and row[-1] for row in rows):
        raise ValueError("Inconsistent visible affine equations")
    free = [i for i in range(width) if i not in pivots]
    particular = [0]*width
    basis = [[0]*len(free) for _ in range(width)]
    for j, source_index in enumerate(free):
        basis[source_index][j] = 1
    for row_index, pivot in enumerate(pivots):
        particular[pivot] = rows[row_index][-1]
        for j, source_index in enumerate(free):
            basis[pivot][j] = -rows[row_index][source_index] % R
    for row, b in zip(matrix, rhs):
        if dot(row, particular) != b % R:
            raise RuntimeError("Affine particular-solution verification failed")
        for j in range(len(free)):
            if dot(row, [basis[i][j] for i in range(width)]):
                raise RuntimeError("Affine kernel verification failed")
    return {"particular": particular, "basis_rows": basis,
            "pivot_columns": pivots, "free_columns": free,
            "rref_augmented": rows}


def reduce_expression(constant, row, fiber):
    constant = (constant+dot(row, fiber["particular"])) % R
    basis = fiber["basis_rows"]
    coefficients = [dot(row, [basis[i][j] for i in range(len(row))])
                    for j in range(len(fiber["free_columns"]))]
    return [constant]+coefficients


def prepare_public_model(pp, original_target, observer_ledger):
    """Validate public binding and rederive the observer's affine fiber."""
    prior.validate_target(pp, original_target)
    if set(observer_ledger) != {"schema", "source_ids", "aliases", "equations", "points"}:
        raise ValueError("Observer ledger must not include extra audit payloads")
    if observer_ledger["schema"] != "CHARE-observer-affine-ledger-v1":
        raise ValueError("Unsupported affine ledger schema")
    for visibility in ["affine_descriptor_visibility", "residual_visibility"]:
        observer_only(original_target, visibility)
    model = {name: original_target[name]
             for name in ["source_ids", "F_columns", "c", "eta",
                          "affine_descriptor_visibility", "residual_visibility"]}
    if original_target["context_object"].get("affine_source_model") != model:
        raise ValueError("Original affine target model binding changed")
    n = len(original_target["nodes"])
    if len(original_target["c"]) != n:
        raise ValueError("Target affine-constant count differs")
    original_names = original_target["source_ids"]
    if len(original_names) != len(set(original_names)):
        raise ValueError("Original target coordinate IDs must be unique")
    if any(len(row) != len(original_names) for row in original_target["F_columns"]):
        raise ValueError("Original target source IDs and columns differ")
    names, resolve = source_resolver(observer_ledger)
    matrix, rhs, equation_ids = [], [], []
    for item in observer_ledger["equations"]:
        observer_only(item)
        if not item.get("evidence_id") or item["equation_id"] in equation_ids:
            raise ValueError("Numerical answer provenance is absent or duplicated")
        equation_ids.append(item["equation_id"])
        row = [0]*len(names)
        for name, coefficient in item["terms"].items():
            index = resolve(name)
            row[index] = (row[index]+scalar(coefficient)) % R
        matrix.append(row)
        rhs.append(scalar(item["rhs"]))
    fiber = affine_fiber(matrix, rhs, len(names))
    targets = []
    for constant, column in zip(original_target["c"], original_target["F_columns"]):
        row = [0]*len(names)
        for name, coefficient in zip(original_names, column):
            index = resolve(name)
            row[index] = (row[index]+scalar(coefficient)) % R
        targets.append(reduce_expression(scalar(constant), row, fiber))
    points, descriptors, handle_ids = [], [], []
    for item in observer_ledger["points"]:
        observer_only(item)
        if (item["handle_id"] in handle_ids or item["handle_id"] == H_HANDLE
                or item.get("recipe", {}).get("kind") != "visible_point_handle"
                or not item.get("recipe", {}).get("observation_id")):
            raise ValueError("Invalid visible source-point recipe")
        constant, row = expression_row(item["expression"], names, resolve)
        points.append(prior.point(item["point"]))
        descriptors.append(reduce_expression(constant, row, fiber))
        handle_ids.append(item["handle_id"])
    # h is always public. Omitting it must never create an artificial failure
    # for a correction whose coefficient is genuinely observer available.
    points.append(prior.point(pp["h"]))
    descriptors.append([1]+[0]*len(fiber["free_columns"]))
    handle_ids.append(H_HANDLE)
    return {"source_order": names, "equation_ids": equation_ids,
            "matrix": matrix, "rhs": rhs, "fiber": fiber,
            "target_columns": targets, "point_columns": descriptors,
            "point_handle_ids": handle_ids, "points": points}


def compile_affine(pp, original_target, observer_ledger):
    """Jointly search all normalized witnesses in the supplied affine span."""
    public = prepare_public_model(pp, original_target, observer_ledger)
    n, m = len(original_target["nodes"]), len(public["point_columns"])
    rows, rhs = [], []
    for i, eta in enumerate(original_target["eta"]):
        row = [0]*(n+m)
        row[i] = scalar(eta)
        rows.append(row)
        rhs.append(0)
    for coordinate in range(len(public["target_columns"][0])):
        rows.append([column[coordinate] for column in public["target_columns"]]
                    +[-column[coordinate] % R for column in public["point_columns"]])
        rhs.append(0)
    rows.append(prior.gamma(original_target["nodes"])+[0]*m)
    rhs.append(R-1)
    solved = prior.scalar_solve(rows, rhs, n+m)
    diagnostic = {name: value for name, value in public.items() if name != "points"}
    diagnostic.update({"joint_matrix": rows, "joint_rhs": rhs,
                       "constant_coordinate_retained": True,
                       "public_h_always_included": True})
    if solved is None:
        return {"status": "NO_REPRESENTED_WITNESS_IN_SUPPLIED_SPAN",
                "diagnostic": diagnostic,
                "scope": "This is not a security claim about all possible encodings."}
    recipe = {"schema": "CHARE-affine-recovery-recipe-v1",
              "setup_id": pp["setup_id"],
              "original_target_sha256": digest(original_target),
              "observer_ledger_sha256": digest(observer_ledger),
              "point_handle_ids": public["point_handle_ids"],
              "x": solved[:n], "point_coefficients": solved[n:]}
    return {"status": "REPRESENTED_CANDIDATE", "recipe": recipe,
            "diagnostic": diagnostic}


def recover_affine(pp, original_target, observer_ledger, compiled_recipe):
    """Use actual coordinates and the original ciphertext/context only.

    An outer comparator must compare the result with the original encapsulator
    output before reporting a verified fixture. This function returns a candidate.
    """
    public = prepare_public_model(pp, original_target, observer_ledger)
    if compiled_recipe.get("schema") != "CHARE-affine-recovery-recipe-v1":
        raise ValueError("Unsupported affine recovery recipe")
    expected_binding = {"setup_id": pp["setup_id"],
                        "original_target_sha256": digest(original_target),
                        "observer_ledger_sha256": digest(observer_ledger),
                        "point_handle_ids": public["point_handle_ids"]}
    for name, value in expected_binding.items():
        if compiled_recipe.get(name) != value:
            raise ValueError("Compiled recovery binding changed: " + name)
    x = [scalar(value) for value in compiled_recipe["x"]]
    weights = [scalar(value) for value in compiled_recipe["point_coefficients"]]
    n, N = len(original_target["nodes"]), pp["N"]
    if len(x) != n or len(weights) != len(public["points"]):
        raise ValueError("Recovery recipe dimensions differ")
    if (any(scalar(eta)*value % R for eta, value in zip(original_target["eta"], x))
            or dot(prior.gamma(original_target["nodes"]), x) != R-1):
        raise ValueError("Residual or gamma*x=-1 condition failed")
    for coordinate in range(len(public["target_columns"][0])):
        left = dot(x, [column[coordinate] for column in public["target_columns"]])
        right = dot(weights, [column[coordinate] for column in public["point_columns"]])
        if left != right:
            raise ValueError("Affine source correction does not match, including its constant")
    q = prior.interpolate(original_target["nodes"], x)
    if len(q) != n or q[-1] != R-1:
        raise ValueError("Interpolant leading coefficient must be -1")
    qh = curve.linear_combination((value, prior.point(pp["T"][k]))
                                 for k, value in enumerate(q))
    terms = [(1, prior.point(pp["Gamma"]))]
    terms += [(-q[k], prior.point(pp["A"][N-n+k])) for k in range(n-1)]
    quotients = []
    for i, node in enumerate(original_target["nodes"]):
        quotient = prior.polynomial_quotient(q, node, x[i])
        quotients.append(quotient)
        terms += [(-value, prior.point(original_target["projections"][i][k]))
                  for k, value in enumerate(quotient)]
    source_correction = curve.linear_combination(zip(weights, public["points"]))
    terms.append((-1, source_correction))
    rh = curve.linear_combination(terms)
    recovered = (curve.pairing(prior.point(original_target["C0"]), rh)
                 * curve.pairing(prior.point(original_target["C1"]), qh))
    context = bytes.fromhex(original_target["context_hex"])
    return {"status": "AFFINE_TINY_CURVE_REPLAY_CANDIDATE",
            "x": x, "gamma": prior.gamma(original_target["nodes"]),
            "gamma_times_x": dot(prior.gamma(original_target["nodes"]), x),
            "q": q, "q_leading_coefficient": q[-1], "quotients": quotients,
            "point_handle_ids": public["point_handle_ids"],
            "point_coefficients": weights,
            "L": prior.point_hex(source_correction),
            "Q_h": prior.point_hex(qh), "R_h": prior.point_hex(rh),
            "GT_hex": recovered.encode().hex(),
            "key_sha256": prior.key_derive(context, recovered),
            "original_context_sha256": hashlib.sha256(context).hexdigest(),
            "original_target_sha256": digest(original_target)}
