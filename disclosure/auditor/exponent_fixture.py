"""Transparent exponent-model fixture ONLY; not a cryptographic implementation.

The linear core receives no source values or setup secrets. This harness owns
them solely to construct and check fixtures. A group element is represented by
its exponent; a pairing multiplies exponents. These tests never establish a
native recovery, generic-group bound, computational hardness, or performance.
"""

from dataclasses import dataclass
from hashlib import sha256
import json

from auditor_core import (ContractError, PointDescriptor, Target, dot,
                          recovery_polynomials, target_digest)


@dataclass
class ExponentFixture:
    target: Target
    capacity_nodes: tuple[int, ...]
    nodes: tuple[int, ...]
    source_values: tuple[int, ...]
    tau: int = 13
    theta: int = 17
    a: int = 7
    alpha: int = 29
    beta: int = 31
    s: int = 19

    def __post_init__(self):
        t, p = self.target, self.target.p
        t.check()
        N, n = len(self.capacity_nodes), len(self.nodes)
        if (n != len(t.eta) or n > N or len(self.source_values) != len(t.source_ids)
                or len(set(u % p for u in self.capacity_nodes)) != N
                or 0 in [u % p for u in self.capacity_nodes]
                or self.tau % p in {0, *(u % p for u in self.capacity_nodes)}
                or not set(self.nodes).issubset(set(self.capacity_nodes))):
            raise ContractError("invalid fixture setup or target")
        gamma = tuple(pow(product([u - v for v in self.nodes if v != u], p), -1, p)
                      for u in self.nodes)
        if tuple(v % p for v in t.gamma) != gamma:
            raise ContractError("gamma must come from original nodes")
        self.points = {"g": 1, "h": self.theta % p}
        self.T = [self.add_point(f"T/{k}", pow(self.tau, k, p) * self.theta) for k in range(N)]
        self.A = [self.add_point(f"A/{k}", self.a * pow(self.tau, k, p) * self.theta)
                  for k in range(N - 1)]
        self.Gamma = self.add_point("Gamma", (self.alpha + self.a * pow(self.tau, N - 1, p)) * self.theta)
        self.X, self.projections = [], []
        source_sum = 0
        for i, u in enumerate(self.nodes):
            xi = (t.offsets[i] + sum(t.F[k][i] * w for k, w in enumerate(self.source_values))
                  + self.beta * t.eta[i] * pow((self.tau - u) % p, -1, p)) % p
            source_sum = (source_sum + xi) % p
            self.X.append(self.add_point(f"original/X/{i}", xi))
            self.projections.append([self.add_point(f"original/projection/{i}/{k}",
                                      (self.tau - u) * pow(self.tau, k, p) * xi * self.theta)
                                     for k in range(N - 1)])
        S = (self.a * pow(self.tau, N - n, p) + source_sum) % p
        self.C0 = self.add_point("original/C0", self.s)
        self.C1 = self.add_point("original/C1", self.s * S)
        ctx = {"instance": "A2-exponent-model", "target_id": t.target_id,
               "snapshot": "original-snapshot", "records": self.X,
               "J": self.nodes, "policy": ["fixture-policy"], "signs": [1],
               "weights": [1], "C0": self.encode(self.points[self.C0]).hex(),
               "C1": self.encode(self.points[self.C1]).hex()}
        self.original_context = json.dumps(ctx, sort_keys=True, separators=(",", ":")).encode()
        self.original_input = self.encode(self.s * self.alpha * self.theta % p)
        self.original_descriptor = target_digest(t)
        self.original_ciphertext = (self.encode(self.points[self.C0]), self.encode(self.points[self.C1]))
        self.original_projection_handles = tuple(tuple(r) for r in self.projections)
        self.original_public_inputs = {handle: self.encode(v) for handle, v in self.points.items()}
        self.descriptors = {}
        self.add_affine("h", (1,) + (0,) * len(t.source_ids), "setup/h")

    def encode(self, exponent):
        return (exponent % self.target.p).to_bytes(max(1, (self.target.p.bit_length() + 7) // 8), "big")

    def add_point(self, handle, exponent):
        if handle in self.points:
            raise ContractError("point handle reuse")
        self.points[handle] = exponent % self.target.p
        return handle

    def add_affine(self, handle, affine, origin, known=True):
        if handle in self.descriptors:
            raise ContractError("descriptor overwrite")
        val = (affine[0] + dot(affine[1:], self.source_values, self.target.p)) * self.theta % self.target.p
        if handle in self.points:
            if self.points[handle] != val:
                raise ContractError("fixture point disagrees with affine descriptor")
        else:
            self.add_point(handle, val)
        desc = PointDescriptor(handle, self.target.source_ids, tuple(affine), origin, known)
        self.descriptors[handle] = desc
        return desc

    def add_pending(self, handle, exponent, origin):
        self.add_point(handle, exponent)
        desc = PointDescriptor(handle, self.target.source_ids, None, origin, True)
        self.descriptors[handle] = desc
        return desc

    def replay(self, result, *, context=None, projection_handles=None):
        """Run formulas on ORIGINAL model handles, and compare ORIGINAL input.

        Outputs only EXPONENT_MODEL_REPLAY_VERIFIED or raises ContractError.
        The independent original input is used only for the final comparison.
        """
        t, p = self.target, self.target.p
        if result.get("status") != "REPRESENTED_CANDIDATE":
            raise ContractError("a formal witness is not a recovery plan")
        if result.get("target_id") != t.target_id or result.get("target_descriptor_digest") != self.original_descriptor:
            raise ContractError("original target or actual affine data changed")
        if not t.execution_metadata_known:
            raise ContractError("execution scalars require observer provenance")
        if (self.encode(self.points[self.C0]), self.encode(self.points[self.C1])) != self.original_ciphertext:
            raise ContractError("original ciphertext bytes changed")
        ctx = self.original_context if context is None else context
        if ctx != self.original_context:
            raise ContractError("original KDF context changed")
        if any(handle not in self.points or self.encode(self.points[handle]) != value
               for handle, value in self.original_public_inputs.items()):
            raise ContractError("original public input bytes changed")
        P = self.projections if projection_handles is None else projection_handles
        N, n = len(self.capacity_nodes), len(self.nodes)
        if (len(P) != n or any(len(r) != N - 1 for r in P)
                or tuple(tuple(r) for r in P) != self.original_projection_handles):
            raise ContractError("requires original full N-1 projection arrays")
        for i, u in enumerate(self.nodes):
            for k in range(N - 1):
                if P[i][k] not in self.points:
                    raise ContractError("missing original projection handle")
                lhs = self.points[self.X[i]] * (self.points[self.T[k + 1]] - u * self.points[self.T[k]]) % p
                if lhs != self.points[P[i][k]]:
                    raise ContractError("full projection check failed")
        r = result["represented"]
        handles, weights, x = r["selected_handles"], r["point_coefficients"], r["x"]
        if len(handles) != len(weights):
            raise ContractError("point recipe dimensions")
        lifted = [0] * (len(t.source_ids) + 1)
        L = 0
        for handle, c in zip(handles, weights):
            if handle not in self.descriptors or handle not in self.points:
                raise ContractError("unregistered source handle")
            desc = self.descriptors[handle]
            if (desc.affine is None or not desc.origin_event or desc.source_ids != t.source_ids
                    or not desc.execution_metadata_known):
                raise ContractError("source handle provenance or affine type")
            lifted = [(v + c * u) % p for v, u in zip(lifted, desc.affine)]
            L = (L + c * self.points[handle]) % p
        expected = [dot(t.offsets, x, p)] + [dot(row, x, p) for row in t.F]
        if lifted != expected or any(e * u % p for e, u in zip(t.eta, x)) or dot(t.gamma, x, p) != (-1) % p:
            raise ContractError("candidate does not represent the actual affine source term")
        q, b = recovery_polynomials(t, self.nodes, r)
        Q = sum(c * self.points[self.T[k]] for k, c in enumerate(q)) % p
        R = (self.points[self.Gamma] -
             sum(q[d] * self.points[self.A[N - n + d]] for d in range(n - 1)) -
             sum(b[i][k] * self.points[P[i][k]] for i in range(n) for k in range(n - 1)) - L) % p
        recovered = (self.points[self.C0] * R + self.points[self.C1] * Q) % p
        encoded = self.encode(recovered)
        if encoded != self.original_input:
            raise ContractError("original encapsulation input not recovered")
        # Framing is fixture-specific; this is not the production hash format.
        framed = len(ctx).to_bytes(4, "big") + ctx + len(encoded).to_bytes(4, "big") + encoded
        return {"status": "EXPONENT_MODEL_REPLAY_VERIFIED", "target_id": t.target_id,
                "full_projection_checks": n * (N - 1), "Q_model_exponent": Q,
                "R_model_exponent": R, "original_input_encoding": encoded.hex(),
                "original_context_sha256": sha256(ctx).hexdigest(),
                "model_kdf_framing_sha256": sha256(framed).hexdigest(), "native_replay": "NOT_RUN"}


def product(values, p):
    out = 1
    for v in values:
        out = out * v % p
    return out
