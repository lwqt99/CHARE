"""CHARE A2 reference linear core. No group or native recovery is implemented.

Inputs are restored, provenance-bearing descriptors on one actual affine fiber.
The caller authenticates these descriptors; this module does not extract source
coefficients from arbitrary group encodings. All arithmetic is in a supplied
prime field. Matrices use rows; capability bases and point lists use columns.
"""

from dataclasses import dataclass
from dataclasses import asdict
from hashlib import sha256
import json
from typing import Optional, Sequence


class ContractError(ValueError):
    pass


def solve(rows, rhs, nvars, p):
    """Return one exact solution (free variables zero), or None.

    Prime p is a setup precondition, not established by this routine.
    """
    if len(rows) != len(rhs) or any(len(r) != nvars for r in rows):
        raise ContractError("linear system dimensions")
    a = [[v % p for v in r] + [b % p] for r, b in zip(rows, rhs)]
    pivots = []
    pos = 0
    for col in range(nvars):
        pivot = next((i for i in range(pos, len(a)) if a[i][col]), None)
        if pivot is None:
            continue
        a[pos], a[pivot] = a[pivot], a[pos]
        inv = pow(a[pos][col], -1, p)
        a[pos] = [(v * inv) % p for v in a[pos]]
        for i in range(len(a)):
            if i != pos and a[i][col]:
                c = a[i][col]
                a[i] = [(v - c * w) % p for v, w in zip(a[i], a[pos])]
        pivots.append(col)
        pos += 1
        if pos == len(a):
            break
    if any(not any(r[:nvars]) and r[-1] for r in a):
        return None
    ans = [0] * nvars
    for row, col in enumerate(pivots):
        ans[col] = a[row][-1]
    return ans


def dot(a, b, p):
    if len(a) != len(b):
        raise ContractError("dot dimensions")
    return sum(x * y for x, y in zip(a, b)) % p


def in_span(v, columns, p):
    if any(len(c) != len(v) for c in columns):
        raise ContractError("span dimensions")
    rows = [[c[i] for c in columns] for i in range(len(v))]
    return solve(rows, v, len(columns), p) is not None


@dataclass(frozen=True)
class Target:
    target_id: str
    p: int
    source_ids: tuple[str, ...]
    F: tuple[tuple[int, ...], ...]
    eta: tuple[int, ...]
    gamma: tuple[int, ...]
    offsets: tuple[int, ...]
    # True only if the recorded solver inputs can be computed from the
    # observer's transcript. A privileged audit value alone does not qualify.
    execution_metadata_known: bool = False

    def check(self):
        d, n = len(self.source_ids), len(self.eta)
        if self.p < 2 or not self.target_id or n == 0:
            raise ContractError("invalid target or field")
        if len(set(self.source_ids)) != d:
            raise ContractError("source aliases must be restored before audit")
        if len(self.F) != d or any(len(r) != n for r in self.F):
            raise ContractError("target matrix dimensions")
        if len(self.gamma) != n or len(self.offsets) != n:
            raise ContractError("target row dimensions")
        if not any(g % self.p for g in self.gamma):
            raise ContractError("zero gamma")


@dataclass(frozen=True)
class PointDescriptor:
    handle: str
    source_ids: tuple[str, ...]
    # Relative to h, (constant, ordinary coefficients). None means the point
    # has other dependence, e.g. a pending polynomial mask, and is excluded.
    affine: Optional[tuple[int, ...]]
    origin_event: str
    execution_metadata_known: bool = False


def target_digest(target):
    """Bind the restored description to the immutable original target record."""
    return sha256(json.dumps(asdict(target), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def formal_audit(target: Target, capability_columns):
    """Exact formal criterion, not an executable attack claim."""
    target.check()
    p, n, d = target.p, len(target.eta), len(target.source_ids)
    U = capability_columns
    if any(len(u) != d for u in U):
        raise ContractError("formal capability dimensions")
    m = len(U)
    rows, rhs = [], []
    for i, eta in enumerate(target.eta):
        rows.append([eta if j == i else 0 for j in range(n)] + [0] * m)
        rhs.append(0)
    for k in range(d):
        rows.append(list(target.F[k]) + [-u[k] for u in U])
        rhs.append(0)
    rows.append(list(target.gamma) + [0] * m)
    rhs.append(-1)
    sol = solve(rows, rhs, n + m, p)
    if sol is not None:
        return {"status": "FORMAL_WITNESS", "x": sol[:n], "formal_coefficients": sol[n:]}
    cert_rows = [list(u) + [0] * n for u in U]
    cert_rhs = [0] * m
    for i in range(n):
        cert_rows.append([target.F[k][i] for k in range(d)] +
                         [target.eta[i] if j == i else 0 for j in range(n)])
        cert_rhs.append(target.gamma[i])
    cert = solve(cert_rows, cert_rhs, d + n, p)
    if cert is None:
        raise AssertionError("field duality failed or input field is invalid")
    return {"status": "PROTECTED", "z": cert[:d], "a": cert[d:],
            "scope": "declared formal source language and actual affine fiber"}


def verify_certificate(target, U, z, a):
    p = target.p
    return (len(z) == len(target.source_ids) and len(a) == len(target.eta)
            and all(dot(u, z, p) == 0 for u in U)
            and all((sum(target.F[k][i] * z[k] for k in range(len(z))) +
                         target.eta[i] * a[i] - target.gamma[i]) % p == 0
                    for i in range(len(a))))


def represented_search(target: Target, points: Sequence[PointDescriptor]):
    """Search the entire declared represented constant span independently.

    Never attempts only the first formal witness. This is complete for the
    supplied affine point span, not for arbitrary omitted recipes. Affine
    offsets are a row of the system, never silently discarded.
    """
    target.check()
    p, n, d = target.p, len(target.eta), len(target.source_ids)
    if len({q.handle for q in points}) != len(points):
        raise ContractError("duplicate point handle")
    selected = []
    for q in points:
        if not q.handle or not q.origin_event or q.source_ids != target.source_ids:
            raise ContractError("point identity, basis or provenance mismatch")
        if q.affine is not None:
            if len(q.affine) != d + 1:
                raise ContractError("point affine dimensions")
            selected.append(q)
    def search(subset):
        m = len(subset)
        rows, rhs = [], []
        for i, eta in enumerate(target.eta):
            rows.append([eta if j == i else 0 for j in range(n)] + [0] * m)
            rhs.append(0)
        lift = [target.offsets] + list(target.F)
        for k, row in enumerate(lift):
            rows.append(list(row) + [-q.affine[k] for q in subset])
            rhs.append(0)
        rows.append(list(target.gamma) + [0] * m)
        rhs.append(-1)
        return solve(rows, rhs, n + m, p)

    audit_sol = search(selected)
    if audit_sol is None:
        return {"state": "NO_CANDIDATE_IN_DECLARED_SPAN",
                "selected_handles": [q.handle for q in selected]}
    known_points = [q for q in selected if q.execution_metadata_known]
    # Search afresh; inspecting only nonzero coefficients of audit_sol repeats
    # the first-witness mistake one level lower. Unused private descriptors
    # must not block a plan that uses exclusively observer-known descriptors.
    known_sol = (search(known_points) if target.execution_metadata_known else None)
    if known_sol is not None:
        return {"state": "REPRESENTED_CANDIDATE", "x": known_sol[:n],
                "point_coefficients": known_sol[n:],
                "selected_handles": [q.handle for q in known_points],
                "audit_span_x": audit_sol[:n],
                "scalar_origin": "deterministic elimination over observer-known descriptors"}
    return {"state": "SCALAR_PROVENANCE_PENDING", "x": audit_sol[:n],
            "point_coefficients": audit_sol[n:],
            "selected_handles": [q.handle for q in selected],
            "scalar_origin": "audit-only descriptors are insufficient"}


def audit(target, capability_columns, points):
    """Keep the formal result and independent represented result separately."""
    target.check()
    if len({q.handle for q in points}) != len(points):
        raise ContractError("duplicate point handle")
    for q in points:
        if not q.handle or not q.origin_event or q.source_ids != target.source_ids:
            raise ContractError("point identity, basis or provenance mismatch")
        if q.affine is not None and len(q.affine) != len(target.source_ids) + 1:
            raise ContractError("point affine dimensions")
        if q.affine is not None and not in_span(q.affine[1:], capability_columns, target.p):
            raise ContractError("represented direction absent from formal capability")
    formal = formal_audit(target, capability_columns)
    if formal["status"] == "PROTECTED":
        return {"status": "PROTECTED", "formal": formal, "target_id": target.target_id,
                "target_descriptor_digest": target_digest(target)}
    represented = represented_search(target, points)
    status = "REPRESENTED_CANDIDATE" if represented["state"] == "REPRESENTED_CANDIDATE" else "FORMAL_WITNESS"
    return {"status": status, "formal": formal, "represented": represented,
            "target_id": target.target_id, "target_descriptor_digest": target_digest(target),
            "native_replay": "NOT_RUN"}


def public_audit(target, capability_columns, certified_nonzero_slots):
    """Conservative public test; never turns its failure into an attack."""
    D = set(certified_nonzero_slots)
    if any(i < 0 or i >= len(target.eta) for i in D):
        raise ContractError("certified slot index")
    relaxed = Target(target.target_id, target.p, target.source_ids, target.F,
                     tuple(int(i in D) for i in range(len(target.eta))),
                     target.gamma, target.offsets, target.execution_metadata_known)
    result = formal_audit(relaxed, capability_columns)
    if result["status"] == "PROTECTED":
        return {"status": "PROTECTED", "certificate": result,
                "certified_nonzero_slots": sorted(D), "scope": "public conservative test"}
    return {"status": "UNCERTIFIED", "certified_nonzero_slots": sorted(D)}


def interpolate(nodes, values, p):
    """Ascending coefficients of the unique polynomial of degree < n."""
    if not nodes or len(nodes) != len(values) or len(set(x % p for x in nodes)) != len(nodes):
        raise ContractError("interpolation nodes")
    q = [0] * len(nodes)
    for i, t in enumerate(nodes):
        b, denom = [1], 1
        for j, u in enumerate(nodes):
            if i == j:
                continue
            nxt = [0] * (len(b) + 1)
            for k, c in enumerate(b):
                nxt[k] = (nxt[k] - u * c) % p
                nxt[k + 1] = (nxt[k + 1] + c) % p
            b = nxt
            denom = denom * (t - u) % p
        scale = values[i] * pow(denom, -1, p) % p
        q = [(v + scale * c) % p for v, c in zip(q, b)]
    return q


def quotient_at(q, t, p):
    """(q(X)-q(t))/(X-t), with ascending coefficients; empty for n=1."""
    if len(q) == 1:
        return []
    b = [0] * (len(q) - 1)
    b[-1] = q[-1] % p
    for k in range(len(b) - 2, -1, -1):
        b[k] = (q[k + 1] + t * b[k + 1]) % p
    return b


def recovery_polynomials(target, nodes, represented):
    if represented.get("state") != "REPRESENTED_CANDIDATE":
        raise ContractError("no provenance-qualified represented candidate")
    if len(nodes) != len(target.eta):
        raise ContractError("target nodes")
    q = interpolate(nodes, represented["x"], target.p)
    if q[-1] % target.p != (-1) % target.p:
        raise ContractError("gamma does not match the original target nodes")
    return q, [quotient_at(q, t, target.p) for t in nodes]
