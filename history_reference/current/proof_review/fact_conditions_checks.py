#!/usr/bin/env python3
"""Independent finite-field checks for CHARE round-3 fact-proof conditions.

Standard-library only.  This is algebra/tape enumeration, not group or native
implementation replay.  Run from any cwd; the default JSON is beside this file.
No code is imported from the manuscript's reference auditor.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED = 2026111503


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def dot(a, b, p):
    return sum(x * y for x, y in zip(a, b)) % p


def matvec(a, x, p):
    return [dot(row, x, p) for row in a]


def rref(a, ncols, p):
    a = [[v % p for v in row] for row in a]
    pivots = []
    r = 0
    for c in range(ncols):
        k = next((k for k in range(r, len(a)) if a[k][c]), None)
        if k is None:
            continue
        a[r], a[k] = a[k], a[r]
        q = pow(a[r][c], -1, p)
        a[r] = [(q * v) % p for v in a[r]]
        for j in range(len(a)):
            if j != r and a[j][c]:
                q = a[j][c]
                a[j] = [(x - q * y) % p for x, y in zip(a[j], a[r])]
        pivots.append(c)
        r += 1
        if r == len(a):
            break
    return a, pivots


def solve(a, b, ncols, p):
    rr, piv = rref([row + [v] for row, v in zip(a, b)], ncols, p)
    if any(not any(row[:ncols]) and row[ncols] for row in rr):
        return None
    x = [0] * ncols
    for i, c in enumerate(piv):
        x[c] = rr[i][ncols]
    return x


def nullspace(a, ncols, p):
    rr, piv = rref(a, ncols, p)
    basis = []
    for f in range(ncols):
        if f in piv:
            continue
        v = [0] * ncols
        v[f] = 1
        for i, c in enumerate(piv):
            v[c] = -rr[i][f] % p
        basis.append(v)
    return basis


def polyadd(a, b, p):
    return [((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
            for i in range(max(len(a), len(b)))]


def polymul(a, b, p):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % p
    return out


def polyeval(a, x, p):
    out = 0
    for v in reversed(a):
        out = (out * x + v) % p
    return out


def divide_linear(a, t, p):
    """Return residue a(t), and q with a(X)=a(t)+(X-t)q(X)."""
    if len(a) == 1:
        return a[0] % p, []
    work = [v % p for v in a]
    q = [0] * (len(a) - 1)
    for k in range(len(a) - 1, 0, -1):
        q[k - 1] = work[k]
        work[k - 1] = (work[k - 1] + t * work[k]) % p
    return work[0], q


def small_exhaustive():
    """3125 one-source/one-pad systems, independent direct pad enumeration."""
    p, t = 5, 1
    taus = [3, 4]
    formal_yes = 0
    numeric_only = 0
    cases_hash = hashlib.sha256()
    for lw, lr, b, p0, p1 in itertools.product(range(p), repeat=5):
        T = [[lr], [b]]
        forcing = [[lw, (p0 + p1 * t) % p], [0, p1]]
        formal = all(solve(T, v, 1, p) is not None for v in forcing)
        # Independent exhaustive search for both partial-fraction coefficients.
        brute_formal = any(
            [lr * a % p, b * a % p] == forcing[0]
            and [lr * q % p, b * q % p] == forcing[1]
            for a, q in itertools.product(range(p), repeat=2)
        )
        assert formal == brute_formal
        formal_yes += formal
        numerical = []
        for tau in taus:
            dw = pow(tau - t, -1, p)
            matches = [dr for dr in range(p)
                       if (lw * dw + lr * dr) % p == 0
                       and ((p0 + p1 * tau) * dw + b * dr) % p == 0]
            numerical.append(bool(matches))
            assert not formal or matches
            numeric_only += bool(matches) and not formal
        cases_hash.update(json.dumps([lw, lr, b, p0, p1, formal, numerical]).encode())
    return {
        "p": p, "N": 2, "nodes": [1, 2], "admissible_tau": taus,
        "systems": p ** 5, "formal_compatible": formal_yes,
        "formal_incompatible": p ** 5 - formal_yes,
        "fixed_setup_compatible_but_formally_incompatible_instances": numeric_only,
        "checked": "linear-solver vs exhaustive rational-coefficient search; every formal success preserves both actual rows for every admissible tau",
        "case_stream_sha256": cases_hash.hexdigest(),
    }


def general_systems():
    """Residue/quotient method vs direct denominator-cleared polynomials."""
    rng = random.Random(SEED)
    p, nodes, ns, nr, nq, nm, nf = 11, [1, 2, 3], 4, 2, 2, 3, 2
    slots = [1, 1, 2, 3]
    A = [[0, 0], [1, 0], [0, 1], [1, 0]]  # One core, two generations of fact 0.
    records = []
    for case in range(24):
        family = ["arbitrary", "constant-compatible", "polynomial-compatible"][case // 8]
        Lr = [[rng.randrange(p) for _ in range(nr)] for _ in range(nq)]
        B = [[rng.randrange(p) for _ in range(nr)] for _ in range(nm)]
        Lw = [[rng.randrange(p) for _ in range(ns)] for _ in range(nq)]
        P = [[[rng.randrange(p) for _ in range(len(nodes))] for _ in range(ns)] for _ in range(nm)]
        if family == "constant-compatible":
            R = [[rng.randrange(p) for _ in range(ns)] for _ in range(nr)]
            Lw = [[sum(Lr[i][j] * R[j][a] for j in range(nr)) % p for a in range(ns)] for i in range(nq)]
            P = [[[sum(B[m][j] * R[j][a] for j in range(nr)) % p, 0, 0]
                  for a in range(ns)] for m in range(nm)]
        if family == "polynomial-compatible":
            Lr, Lw = [[0] * nr for _ in range(nq)], [[0] * ns for _ in range(nq)]
            R = [[[rng.randrange(p) for _ in range(3)] for _ in range(ns)] for _ in range(nr)]
            P = [[[sum(B[m][j] * R[j][a][k] for j in range(nr)) % p for k in range(3)]
                  for a in range(ns)] for m in range(nm)]
        y0 = [rng.randrange(2) for _ in range(nf)]
        y1 = [1 - y0[0], 1 - y0[1]]
        d = [(b - a) % p for a, b in zip(y0, y1)]
        ad = matvec(A, d, p)
        T = Lr + B
        H = nullspace([list(col) for col in zip(*T)], nq + nm, p)
        residues = {t: [0] * (nq + nm) for t in nodes}
        quotients = [[0] * (nq + nm) for _ in range(2)]
        for a, t in enumerate(slots):
            for j in range(nq):
                residues[t][j] = (residues[t][j] + Lw[j][a] * ad[a]) % p
            for m in range(nm):
                u, q = divide_linear(P[m][a], t, p)
                residues[t][nq + m] = (residues[t][nq + m] + u * ad[a]) % p
                for k in range(2):
                    quotients[k][nq + m] = (quotients[k][nq + m] + q[k] * ad[a]) % p
        forcing = list(residues.values()) + quotients
        formal = all(not any(dot(h, v, p) for h in H) for v in forcing)

        # Independently form D(X)g(X), without polynomial division.
        clear = [[0] * 5 for _ in range(nq + nm)]
        for a, t in enumerate(slots):
            other = [1]
            for node in nodes:
                if node != t:
                    other = polymul(other, [-node % p, 1], p)
            for row in range(nq + nm):
                poly = [Lw[row][a]] if row < nq else P[row - nq][a]
                term = [(v * ad[a]) % p for v in polymul(poly, other, p)]
                clear[row] = polyadd(clear[row], term, p)
        image = {tuple(matvec(T, v, p)) for v in itertools.product(range(p), repeat=nr)}
        direct = all(tuple(row[k] for row in clear) in image for k in range(5))
        assert formal == direct
        if family != "arbitrary":
            assert formal
        checked_taus = []
        witness = None
        if formal:
            vi = {t: solve(T, v, nr, p) for t, v in residues.items()}
            vk = [solve(T, v, nr, p) for v in quotients]
            for tau in range(p):
                if tau == 0 or tau in nodes:
                    continue
                beta = 2
                dw = [(beta * ad[a] * pow(tau - slots[a], -1, p)) % p for a in range(ns)]
                dr = [(-beta * (sum(vi[t][j] * pow(tau - t, -1, p) for t in nodes)
                                + sum(vk[k][j] * pow(tau, k, p) for k in range(2)))) % p for j in range(nr)]
                assert all((dot(Lw[j], dw, p) + dot(Lr[j], dr, p)) % p == 0 for j in range(nq))
                assert all((sum(polyeval(P[m][a], tau, p) * dw[a] for a in range(ns))
                            + dot(B[m], dr, p)) % p == 0 for m in range(nm))
                checked_taus.append(tau)
        else:
            h = next(h for h in H if any(dot(h, v, p) for v in forcing))
            poly = [dot(h, [row[k] for row in clear], p) for k in range(5)]
            assert any(poly)
            degree = max(k for k, c in enumerate(poly) if c)
            assert degree <= 2 * len(nodes) - 2
            roots = [tau for tau in range(p) if tau and tau not in nodes and polyeval(poly, tau, p) == 0]
            assert len(roots) <= degree
            witness = {"left_kernel_row": h, "cleared_difference": poly, "degree": degree, "admissible_roots": roots}
        inp = {"family": family, "Lw": Lw, "Lr": Lr, "B": B, "point_polynomials": P,
               "A": A, "slots": slots, "y0": y0, "y1": y1}
        records.append({"case": case, "input_sha256": digest(inp), "input": inp,
                        "formal_compatible": formal, "direct_cleared_test": direct,
                        "checked_tau": checked_taus, "witness": witness})
    return {"seed": SEED, "p": p, "nodes": nodes, "systems": len(records),
            "formal_compatible": sum(r["formal_compatible"] for r in records),
            "method": "left-kernel partial fractions vs independent full enumeration of im(T) on every coefficient of D(X)g(X)",
            "records": records}


def joint_tape():
    p, tau, t, beta, bits = 5, 3, 1, 2, 3
    dw = beta * pow(tau - t, -1, p) % p
    image = set()
    trace_hash = hashlib.sha256()

    def transcript(w1, w2, r, R1, Rr, fact):
        ell = (w1 - w2) % p
        k = (ell * ell + 1) % p  # A genuinely adaptive, public-prefix coefficient.
        E = ((w1 - fact * beta * pow(tau - t, -1, p)) % p,
             (w2 - fact * beta * pow(tau - t, -1, p)) % p)
        F = (((tau - t) * w1 - fact * beta) % p,
             ((tau - t) * w2 - fact * beta) % p)
        C = ((k * (tau - t) * w1 + r) % p,
             (k * (tau - t) * w2 + r) % p)
        return (ell, k, E, F, C, w1 ^ R1, r ^ Rr)

    for w1, w2, r, R1, Rr in itertools.product(range(p), range(p), range(p), range(2 ** bits), range(2 ** bits)):
        old = (w1, w2, r, R1, Rr)
        tr = transcript(*old, 0)
        k = tr[1]
        w1p, w2p, rp = (w1 + dw) % p, (w2 + dw) % p, (r - beta * k) % p
        new = (w1p, w2p, rp, R1 ^ w1 ^ w1p, Rr ^ r ^ rp)
        assert tr == transcript(*new, 1)
        assert (w1p - dw) % p == w1 and (w2p - dw) % p == w2
        assert (rp + beta * k) % p == r
        assert new[3] ^ w1p ^ w1 == R1 and new[4] ^ rp ^ r == Rr
        image.add(new)
        trace_hash.update(json.dumps([old, new, tr]).encode())
    expected = p ** 3 * 2 ** (2 * bits)
    assert len(image) == expected
    conditional_answers = sorted({R for w in range(p) for R in range(2 ** bits) if (w ^ R) == 0})
    return {
        "p": p, "tau": tau, "slot": t, "beta": beta, "oracle_bits": bits,
        "joint_tapes": expected, "unique_images": len(image), "failures": 0,
        "source_shift": dw, "pad_shift": "-beta * (ell^2+1); ell=w1-w2",
        "checked": "all canonical first/projection exponents, numerical ell, both whole-point exponents, two original payloads, inverse and unique images",
        "payload_zero_reserved_answer_support": conditional_answers,
        "payload_conditioned_answer_uniform_on_all_strings": False,
        "trace_sha256": trace_hash.hexdigest(),
    }


def boundary_examples():
    p, N, nodes, beta = 11, 2, [1, 2], 1
    admissible = [x for x in range(p) if x and x not in nodes]
    differences = {str(x): (beta * (x - 3) * pow(x - 1, -1, p)) % p for x in admissible}
    assert [int(x) for x, v in differences.items() if v == 0] == [3]
    # The canonical F0 example has a world-dependent offset: excluded by L131.
    tau, w, y0, y1 = 4, 6, 0, 1
    wp = (w + beta * pow(tau - 1, -1, p)) % p
    F0 = ((tau - 1) * w - y0 * beta) % p
    F1 = ((tau - 1) * wp - y1 * beta) % p
    assert F0 == F1
    # Rebinding one physical source to a new fact breaks immutable generation.
    old_E = w
    new_E0 = w
    new_E1 = (w - beta * pow(tau - 1, -1, p)) % p
    assert (old_E - new_E0) % p != (old_E - new_E1) % p
    # Hidden external numeric terms are not the declared numerical language.
    fiber = [(s, z) for s, z in itertools.product(range(5), repeat=2) if (s + z) % 5 == 0]
    assert len(fiber) == 5
    source_selected_pair_images = [(w + (1 if w == 0 else 0)) % 5 for w in range(5)]
    assert len(set(source_selected_pair_images)) == 4
    # A private coefficient a=r cannot be frozen as if selected by the prefix.
    private_r = 2
    frozen_pad_shift = -pow(private_r, -1, 5) % 5
    actual_output_shift = (1 + (private_r + frozen_pad_shift) ** 2 - private_r ** 2) % 5
    assert (1 + private_r * frozen_pad_shift) % 5 == 0 and actual_output_shift != 0
    return {
        "formal_vs_sampled_setup": {
            "p": p, "N": N, "nodes": nodes, "point_polynomial": [-3, 1],
            "fact_difference": 1, "formal_residue_at_1": -2 % p, "formal_quotient": 1,
            "formal_status": "INCOMPATIBLE", "rational_difference": "(X-3)/(X-1)",
            "all_node_denominator_cleared": "(X-3)(X-2)", "cleared_degree": 2,
            "actual_differences": differences, "exceptional_admissible_tau": [3],
            "fixed_witness_collision_probability": "1/8", "paper_upper_bound": "2/8",
            "interpretation": "legal-model root event, not a contradiction to the formal theorem",
        },
        "canonical_offset_misregistration": {
            "p": p, "tau": tau, "w0": w, "w1": wp, "F0": F0, "F1": F1,
            "source_displacement_in_projection": beta, "offset_displacement": -beta % p,
            "interpretation": "model violation if canonical -y*beta is frozen or omitted as a common affine offset; canonical records belong to their own shift identity",
        },
        "alias_fact_rebinding": {
            "p": p, "tau": tau, "old_first_point_exponent": old_E,
            "new_first_point_exponents": [new_E0, new_E1],
            "visible_old_minus_new": [(old_E - new_E0) % p, (old_E - new_E1) % p],
            "interpretation": "invalid immutable-source/fact-map contract; fresh issuance cannot be implemented as an alias with a different fact displacement",
        },
        "unmodelled_external_scalar_offset": {
            "p": 5, "observation": "ell=s+z=0", "conditional_pairs": fiber,
            "conditional_joint_support_size": 5, "product_of_marginal_support_sizes": 25,
            "interpretation": "independence fails if an unopened external z is hidden in a numerical offset; such a release is outside the stated numerical source language",
        },
        "source_selected_fact_pair": {
            "p": 5, "purported_shift": "w -> w + 1[w=0]",
            "images": source_selected_pair_images, "unique_images": 4,
            "interpretation": "an after-sampling fact pair can make the purported translation nonbijective; excluded by fixing the pair independently before fresh sources",
        },
        "private_coefficient_frozen_as_public": {
            "p": 5, "actual_release": "w+r^2", "incorrect_linear_description": "w+a*r with private a=r",
            "w_shift": 1, "r": private_r, "r_shift_from_frozen_coefficient": frozen_pad_shift,
            "frozen_description_output_shift": 0, "actual_regenerated_output_shift": actual_output_shift,
            "interpretation": "a private source-dependent coefficient cannot be frozen as a common returned-prefix coefficient; this nonlinear release is outside the source contract",
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, default=ROOT / "fact_conditions_checks.json")
    args = ap.parse_args()
    out = {
        "schema": "chare-round3-fact-conditions-1", "review_date": "2026-11-15",
        "baseline_sha256": "0f5ceafc966e946b35511e357e3d6194d7eaa9b99e48016acb65a9ac7245b845",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "evidence_scope": "independent exact finite-field algebra and finite joint-tape enumeration; not native or curve replay and not a cryptographic security proof",
        "small_exhaustive": small_exhaustive(), "general_systems": general_systems(),
        "joint_tape": joint_tape(), "boundary_examples": boundary_examples(),
        "assertion_failures": 0,
    }
    args.output.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "small_systems": out["small_exhaustive"]["systems"],
                      "general_systems": out["general_systems"]["systems"],
                      "joint_tapes": out["joint_tape"]["joint_tapes"], "assertion_failures": 0}))


if __name__ == "__main__":
    main()
