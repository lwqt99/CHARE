"""Previous delivered polynomial auditor and public recovery compiler.
The functions are copied verbatim; the new adapter supplies actual coordinates.
"""
# Original source SHA256: 59c41a5011a2686cd5ddab7fc9fe32aa611037d2c3e462b507f38cb99577b986

def trim(f, p):
    f = [x % p for x in f]
    while len(f) > 1 and not f[-1]:
        f.pop()
    return f or [0]


def add(f, g, p):
    n = max(len(f), len(g))
    return trim([(f[i] if i < len(f) else 0) +
                 (g[i] if i < len(g) else 0) for i in range(n)], p)


def scale(f, c, p):
    return trim([c * x for x in f], p)


def mul(f, g, p):
    out = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        for j, b in enumerate(g):
            out[i+j] = (out[i+j] + a*b) % p
    return trim(out, p)


def evaluate(f, x, p):
    result = 0
    for a in reversed(f):
        result = (result*x + a) % p
    return result


def vanishing(nodes, p):
    out = [1]
    for t in nodes:
        out = mul(out, [-t, 1], p)
    return out


def divide(f, g, p):
    f, g = trim(f, p), trim(g, p)
    if g == [0]:
        raise ZeroDivisionError
    quotient = [0] * max(1, len(f)-len(g)+1)
    inv = pow(g[-1], -1, p)
    while f != [0] and len(f) >= len(g):
        j = len(f)-len(g)
        c = f[-1]*inv % p
        quotient[j] = c
        f = add(f, [0]*j + scale(g, -c, p), p)
    return trim(quotient, p), f


def gcd(f, g, p):
    while trim(g, p) != [0]:
        f, g = g, divide(f, g, p)[1]
    f = trim(f, p)
    return scale(f, pow(f[-1], -1, p), p) if f != [0] else f


def interpolate(nodes, values, p):
    out = [0]
    for i, t in enumerate(nodes):
        others = nodes[:i]+nodes[i+1:]
        basis = vanishing(others, p)
        factor = values[i] * pow(evaluate(basis, t, p), -1, p) % p
        out = add(out, scale(basis, factor, p), p)
    return out


def audit_enrollment(nodes, rows, permitted_unused_nodes, p):
    """Requires represented rows and independently established old safety."""
    polynomials = [interpolate(nodes, row, p) for row in rows]
    common = [0]
    for f in polynomials:
        common = gcd(common, f, p)
    candidates = []
    witnesses = []
    for a in permitted_unused_nodes:
        if a in nodes:
            raise ValueError('a reserved node is already active')
        bad = next((j for j, f in enumerate(polynomials)
                    if evaluate(f, a, p)), None)
        if bad is None:
            candidates.append(a)
        else:
            qp = vanishing(nodes, p)
            lam = -evaluate(polynomials[bad], a, p) * pow(evaluate(qp, a, p), -1, p) % p
            witnesses.append({'node': a, 'basis_row': bad,
                              'target_gamma_value': lam})
    return {'admissible_nodes': candidates, 'common_gcd': common,
            'rejected_witnesses': witnesses}


def audit_enrollment_with_plans(nodes, retained_rows, pending_rows,
                               permitted_unused_nodes, p):
    """Reserve every still-completable, represented planned core direction.

    retained_rows must be the complete strengthened message capability after
    ordinary-mask grants and original dependency restoration, including latent
    mixed outputs after correction; raw uncorrected pure-core intersection is
    not sufficient for this interface.

The independent protected-pad service bounds all of a plan's visible prefixes
by its prescribed complete output. This wrapper does not forget pending plans
merely because a strict prefix currently has zero pure-core capability.
"""
    return audit_enrollment(nodes, list(retained_rows)+list(pending_rows),
                            permitted_unused_nodes, p)


def recover(ops, public, old_nodes, f, new_node, retained_point, ciphertext, p):
    """Compile q and R using public projections and the original ciphertext."""
    qp = vanishing(old_nodes, p)
    fa = evaluate(f, new_node, p)
    if not fa:
        raise ValueError('no violating direction: enrollment is compatible')
    zeta = evaluate(qp, new_node, p) * pow(fa, -1, p) % p
    q = add(scale(f, zeta, p), scale(qp, -1, p), p)
    nodes = old_nodes+[new_node]
    n, capacity = len(nodes), public['N']
    assert len(q) == n and q[-1] == p-1
    assert evaluate(q, new_node, p) == 0
    qpoint = ops.zero()
    for d, coef in enumerate(q):
        qpoint = ops.plus(qpoint, ops.times(coef, public['T'][d]))
    rpoint = public['Gamma']
    for d in range(n-1):
        rpoint = ops.plus(rpoint, ops.times(-q[d], public['A'][capacity-n+d]))
    for t in nodes:
        quotient, remainder = divide(add(q, [-evaluate(q, t, p)], p), [-t, 1], p)
        assert remainder == [0]
        for d, coef in enumerate(quotient):
            rpoint = ops.plus(rpoint, ops.times(-coef, public['roots'][t][d]))
    rpoint = ops.plus(rpoint, ops.times(-zeta, retained_point))
    answer = ops.plus(ops.pairing(ciphertext[0], rpoint),
                      ops.pairing(ciphertext[1], qpoint))
    return answer, {'q_ascending': q, 'zeta': zeta,
                    'gamma_value': -pow(zeta, -1, p) % p}
