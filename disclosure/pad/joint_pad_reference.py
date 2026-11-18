#!/usr/bin/env python3
"""CHARE A2: independent exact linear pad-capability reference.

Stdlib only. This is a coefficient/representation checker, not a group library,
generic-group security experiment, or parser for arbitrary source disclosures.
It imports no CHARE implementation or earlier verification code.

Input: JSON matrices with immutable core/pad IDs, original contribution IDs,
visibility flags, and represented pad-only observations. All input coefficients
are reduced modulo the supplied prime. Actual scalar answers are retained and
checked for linear consistency. Group-point provenance remains a caller duty.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def rref(rows: list[list[int]], p: int, ncols: int | None = None,
         pivot_width: int | None = None) -> tuple[list[list[int]], list[int]]:
    """Exact RREF; optional trailing columns are carried as certificates."""
    if ncols is None:
        ncols = len(rows[0]) if rows else 0
    if any(len(row) != ncols for row in rows):
        raise ValueError("nonrectangular matrix")
    matrix = [[x % p for x in row] for row in rows]
    width = ncols if pivot_width is None else pivot_width
    if not 0 <= width <= ncols:
        raise ValueError("invalid pivot width")
    pivots: list[int] = []
    lead = 0
    for col in range(width):
        pivot = next((i for i in range(lead, len(matrix)) if matrix[i][col]), None)
        if pivot is None:
            continue
        matrix[lead], matrix[pivot] = matrix[pivot], matrix[lead]
        inverse = pow(matrix[lead][col], -1, p)
        matrix[lead] = [inverse * x % p for x in matrix[lead]]
        for i, row in enumerate(matrix):
            if i != lead and row[col]:
                scale = row[col]
                matrix[i] = [(x - scale * y) % p
                             for x, y in zip(row, matrix[lead])]
        pivots.append(col)
        lead += 1
        if lead == len(matrix):
            break
    return matrix, pivots


def nullspace(rows: list[list[int]], p: int, ncols: int) -> list[list[int]]:
    reduced, pivots = rref(rows, p, ncols)
    result = []
    for free in (j for j in range(ncols) if j not in pivots):
        vector = [0] * ncols
        vector[free] = 1
        for row, pivot in zip(reduced, pivots):
            vector[pivot] = -row[free] % p
        result.append(vector)
    return result


def row_basis(rows: list[list[int]], p: int, width: int) -> list[list[int]]:
    reduced, pivots = rref(rows, p, width)
    return reduced[:len(pivots)]


def combine(coefficients: list[int], rows: list[list[int]], p: int,
            width: int) -> list[int]:
    if len(coefficients) != len(rows):
        raise ValueError("coefficient length mismatch")
    return [sum(c * row[j] for c, row in zip(coefficients, rows)) % p
            for j in range(width)]


def _integer(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _unique_ids(ids: list[Any], kind: str) -> None:
    if any(not isinstance(x, str) or not x for x in ids) or len(set(ids)) != len(ids):
        raise ValueError(f"{kind} IDs must be distinct nonempty strings")


def _row(row: Any, width: int, p: int, name: str) -> list[int]:
    if not isinstance(row, list) or len(row) != width or not all(_integer(x) for x in row):
        raise ValueError(f"{name} is not an integer row of width {width}")
    return [x % p for x in row]


def inspect_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    """Return a basis and replayable certificates for cB=dL, u=cA.

    Prime-field arithmetic is a precondition. The reference does not run a
    probabilistic primality test on caller-supplied cryptographic parameters.
    A composite modulus can make modular inversion fail and is unsupported.
    """
    p = ledger["field_prime"]
    if not _integer(p) or p < 2:
        raise ValueError("field_prime must be an integer prime >= 2")
    if ledger.get("observation_scope", "pad_only_linear") != "pad_only_linear":
        raise ValueError("mixed or nonlinear observations require the full source ledger")
    mask_mode = ledger.get("mask_mode")
    if mask_mode not in {"core_only", "corrected_actual", "message_game_grant"}:
        raise ValueError("declare mask_mode: core_only, corrected_actual, or message_game_grant")
    if mask_mode == "corrected_actual" and not ledger.get("mask_correction_provenance"):
        raise ValueError("actual corrected handles require recorded mask-correction provenance")
    core_ids, pad_ids = ledger["core_ids"], ledger["pad_ids"]
    _unique_ids(core_ids, "core")
    _unique_ids(pad_ids, "pad")
    if set(core_ids) & set(pad_ids):
        raise ValueError("core and pad identities must be disjoint")
    n, q = len(core_ids), len(pad_ids)
    originals = ledger["contributions"]
    observations = ledger.get("pad_observations", [])
    _unique_ids([x["id"] for x in originals], "contribution")
    _unique_ids([x["id"] for x in observations], "observation")
    all_ids = {x["id"] for x in originals}
    for alias, original in ledger.get("aliases", {}).items():
        if alias in all_ids or original not in all_ids:
            raise ValueError("aliases must refer directly to an existing original contribution")
    visible = []
    for entry in originals:
        if type(entry.get("visible")) is not bool:
            raise ValueError("every original row needs an explicit visibility flag")
        copied = dict(entry)
        copied["a"] = _row(entry["a"], n, p, entry["id"] + ".a")
        copied["b"] = _row(entry["b"], q, p, entry["id"] + ".b")
        if entry["visible"]:
            if not isinstance(entry.get("handle"), str) or not entry["handle"]:
                raise ValueError("visible contributions require actual retained handle names")
            visible.append(copied)
    pad_rows, scalar_augmented = [], []
    for entry in observations:
        row = _row(entry["row"], q, p, entry["id"] + ".row")
        if entry.get("source_family", "pad_only") != "pad_only":
            raise ValueError("a mixed observation cannot be relabeled as pad-only")
        representation = entry["representation"]
        kind = representation.get("kind")
        if kind not in {"scalar", "h_point"}:
            raise ValueError("pad observations need an actual scalar or an isolated h-point")
        if not isinstance(representation.get("handle"), str) or not representation["handle"]:
            raise ValueError("pad observation lacks a representation handle")
        if kind == "scalar":
            value = representation.get("value")
            if not _integer(value):
                raise ValueError("actual scalar value must be retained")
            scalar_augmented.append(row + [value % p])
        pad_rows.append(row)
    reduced, _ = rref(scalar_augmented, p, q + 1, pivot_width=q)
    if any(not any(row[:q]) and row[q] for row in reduced):
        raise ValueError("inconsistent actual scalar answers")
    a = [entry["a"] for entry in visible]
    b = [entry["b"] for entry in visible]
    m, ell = len(visible), len(observations)
    # E (c,d)^T = 0 is exactly cB-dL=0. Missing contributions have c=0.
    equations = [[b[j][e] for j in range(m)] +
                 [-pad_rows[t][e] % p for t in range(ell)] for e in range(q)]
    kernel = nullspace(equations, p, m + ell)
    represented = [combine(z[:m], a, p, n) + z for z in kernel]
    reduced, pivots = rref(represented, p, n + m + ell, pivot_width=n)
    basis = []
    for row in reduced[:len(pivots)]:
        u, c, d = row[:n], row[n:n+m], row[n+m:]
        left, right = combine(c, b, p, q), combine(d, pad_rows, p, q)
        assert left == right and u == combine(c, a, p, n)
        operations = []
        for value, entry in zip(c, visible):
            if value:
                operations.append({"coefficient_mod_p": value, "kind": "contribution",
                                   "source_id": entry["id"], "handle": entry["handle"]})
        for value, entry in zip(d, observations):
            if value:
                representation = entry["representation"]
                operation = {"coefficient_mod_p": -value % p,
                             "kind": "pad_scalar_times_h" if representation["kind"] == "scalar" else "pad_h_point",
                             "source_id": entry["id"], "handle": representation["handle"]}
                if representation["kind"] == "scalar":
                    operation["actual_scalar_mod_p"] = representation["value"] % p
                operations.append(operation)
        basis.append({"core_direction": u,
                      "contribution_coefficients": {x["id"]: value for x, value in zip(visible, c) if value},
                      "pad_observation_coefficients_d": {x["id"]: value for x, value in zip(observations, d) if value},
                      "represented_pad_elimination": {"cB": left, "dL": right},
                      "operation_recipe": operations})
    return {"schema": "CHARE-A2-joint-pad-certificate-v1", "field_prime": p,
            "scope": "Exact formal linear capability with represented pad-only observations",
            "mask_mode": mask_mode,
            "physical_recipe_eligible": mask_mode != "message_game_grant",
            "actual_group_replay": "NOT_RUN",
            "execution_qualification": "Recipes use declared corrected handles; their authenticity and any mask corrections must be verified by the caller",
            "core_ids": core_ids, "pad_ids": pad_ids,
            "visible_contribution_ids": [x["id"] for x in visible],
            "observation_ids": [x["id"] for x in observations],
            "joint_constraint_kernel_dimension": len(kernel),
            "core_capability_dimension": len(basis), "basis": basis,
            "not_verified": ["group-point authenticity/provenance", "nonlinear observations",
                             "mixed core/mask/pad observations", "prime-field parameter generation",
                             "native prototype behavior or cryptographic security"]}


def verify_certificate(ledger: dict[str, Any], result: dict[str, Any]) -> None:
    """Check each returned representation without recomputing the nullspace.

    This verifies soundness of the supplied basis recipes. Completeness follows
    from the kernel construction/proof, with separate finite exhaustive tests.
    """
    p, n, q = ledger["field_prime"], len(ledger["core_ids"]), len(ledger["pad_ids"])
    contributions = {x["id"]: x for x in ledger["contributions"] if x["visible"]}
    observations = {x["id"]: x for x in ledger.get("pad_observations", [])}
    for item in result["basis"]:
        c = item["contribution_coefficients"]
        d = item["pad_observation_coefficients_d"]
        if not (set(c) <= contributions.keys() and set(d) <= observations.keys()):
            raise ValueError("certificate uses an unavailable original source")
        core = [sum(coef * contributions[name]["a"][j] for name, coef in c.items()) % p for j in range(n)]
        pad1 = [sum(coef * contributions[name]["b"][j] for name, coef in c.items()) % p for j in range(q)]
        pad2 = [sum(coef * observations[name]["row"][j] for name, coef in d.items()) % p for j in range(q)]
        if core != item["core_direction"]:
            raise ValueError("certificate core direction is incorrect")
        if not (pad1 == pad2 == item["represented_pad_elimination"]["cB"] == item["represented_pad_elimination"]["dL"]):
            raise ValueError("certificate does not eliminate represented pads")
        operation_c, operation_d = {}, {}
        for operation in item["operation_recipe"]:
            ident, value = operation["source_id"], operation["coefficient_mod_p"] % p
            if operation["kind"] == "contribution":
                if ident not in contributions or operation["handle"] != contributions[ident]["handle"]:
                    raise ValueError("recipe uses an unavailable contribution handle")
                operation_c[ident] = (operation_c.get(ident, 0)+value) % p
            else:
                if ident not in observations:
                    raise ValueError("recipe uses an unavailable pad observation")
                representation = observations[ident]["representation"]
                expected_kind = "pad_scalar_times_h" if representation["kind"] == "scalar" else "pad_h_point"
                if operation["kind"] != expected_kind or operation["handle"] != representation["handle"]:
                    raise ValueError("recipe pad representation is incorrect")
                if representation["kind"] == "scalar" and operation.get("actual_scalar_mod_p") != representation["value"] % p:
                    raise ValueError("recipe changed an actual scalar answer")
                operation_d[ident] = (operation_d.get(ident, 0)-value) % p
        normalized = lambda mapping: {key: value % p for key, value in mapping.items() if value % p}
        if normalized(operation_c) != normalized(c) or normalized(operation_d) != normalized(d):
            raise ValueError("operation recipe disagrees with its coefficient certificate")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    ledger = json.loads(arguments.ledger.read_text(encoding="utf-8"))
    result = inspect_ledger(ledger)
    verify_certificate(ledger, result)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
