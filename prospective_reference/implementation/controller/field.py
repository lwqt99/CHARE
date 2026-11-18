"""Exact prime-field linear algebra for the public coefficient reference controller.

There is no group backend, random oracle, scalar-secret input, or cryptographic
sampling here. Empty matrices require an explicit column count where needed.
"""
from itertools import combinations


def is_prime64(n):
    if not isinstance(n, int) or isinstance(n, bool) or n < 2 or n >= 1 << 64:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rref(rows, p, ncols=None):
    data = [list(row) for row in rows]
    n = ncols if ncols is not None else (len(data[0]) if data else 0)
    if any(len(row) != n for row in data):
        raise ValueError("inconsistent matrix width")
    a = [[v % p for v in row] for row in data]
    pivots, k = [], 0
    for col in range(n):
        pivot = next((i for i in range(k, len(a)) if a[i][col]), None)
        if pivot is None:
            continue
        a[k], a[pivot] = a[pivot], a[k]
        z = pow(a[k][col], -1, p)
        a[k] = [x * z % p for x in a[k]]
        for i in range(len(a)):
            if i != k and a[i][col]:
                z = a[i][col]
                a[i] = [(x - z * y) % p for x, y in zip(a[i], a[k])]
        pivots.append(col)
        k += 1
        if k == len(a):
            break
    return tuple(tuple(row) for row in a[:k]), tuple(pivots)


def basis(rows, p, ncols=None):
    return rref(rows, p, ncols)[0]


def nullspace(rows, ncols, p):
    a, pivots = rref(rows, p, ncols)
    out = []
    for free in range(ncols):
        if free in pivots:
            continue
        v = [0] * ncols
        v[free] = 1
        for i, pivot in enumerate(pivots):
            v[pivot] = -a[i][free] % p
        out.append(tuple(v))
    return tuple(out)


def in_span(v, rows, p):
    rows = tuple(rows)
    return len(basis(rows + (tuple(v),), p, len(v))) == len(basis(rows, p, len(v)))


def dot(a, b, p):
    return sum(x * y for x, y in zip(a, b)) % p


def lincomb(c, rows, ncols, p):
    return tuple(sum(c[i] * rows[i][j] for i in range(len(rows))) % p
                 for j in range(ncols))


def peval(coefficients, x, p):
    out = 0
    for a in reversed(coefficients):
        out = (out * x + a) % p
    return out


def pmul(a, b, p):
    c = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i + j] = (c[i + j] + x * y) % p
    return tuple(c)


def trim(a, p):
    a = [x % p for x in a]
    while a and a[-1] == 0:
        a.pop()
    return tuple(a)


def interpolate(nodes, values, p):
    out = [0] * len(nodes)
    for i, x in enumerate(nodes):
        numer, denom = (1,), 1
        for j, y in enumerate(nodes):
            if j != i:
                numer = pmul(numer, (-y, 1), p)
                denom = denom * (x - y) % p
        scale = values[i] * pow(denom, -1, p) % p
        for j, c in enumerate(numer):
            out[j] = (out[j] + scale * c) % p
    return trim(out, p)


def joint_capability(core_rows, pad_rows, pad_observations, p, ncores, npads):
    """Projection of span([A B], [0 L]) intersected with zero pad columns.

    It covers visible rows or a supplied potential-completion superledger.
    It is NOT a random-oracle/delivery restoration implementation.
    """
    if len(core_rows) != len(pad_rows):
        raise ValueError("core/pad row count mismatch")
    m, q = len(core_rows), len(pad_observations)
    constraints = [tuple(pad_rows[i][j] for i in range(m)) +
                   tuple(-pad_observations[t][j] for t in range(q))
                   for j in range(npads)]
    kernel = nullspace(constraints, m + q, p)
    return basis((lincomb(v[:m], core_rows, ncores, p) for v in kernel), p, ncores)


def gamma(nodes, target_indices, p):
    vals = []
    for i in target_indices:
        denom = 1
        for j in target_indices:
            if j != i:
                denom = denom * (nodes[i] - nodes[j]) % p
        vals.append(pow(denom, -1, p))
    return tuple(vals)


def target_witness(space, nodes, target_indices, p):
    """Exact canonical empty-policy formal witness, normalized gamma*x=-1."""
    space = basis(space, p, len(nodes))
    wanted = tuple(target_indices)
    outside = [j for j in range(len(nodes)) if j not in wanted]
    constraints = [tuple(row[j] for row in space) for j in outside]
    g = gamma(nodes, wanted, p)
    for c in nullspace(constraints, len(space), p):
        u = lincomb(c, space, len(nodes), p)
        value = dot(g, (u[i] for i in wanted), p)
        if value:
            factor = -pow(value, -1, p) % p
            return {"direction": [factor * x % p for x in u],
                    "target_indices": list(wanted), "functional": p - 1,
                    "normalization": "gamma*x = -1 (mod p)",
                    "representation_level": "formal_coefficient_witness_only"}
    return None


def universal_witness(space, nodes, p, enumeration_limit=12):
    """Find a witness for some target, never claim native recovery.

    Large dictionaries may return None without proving safety. The controller's
    positive certificate is membership in its proved polynomial envelope.
    """
    if len(nodes) > enumeration_limit:
        return None
    for size in range(1, len(nodes) + 1):
        for inds in combinations(range(len(nodes)), size):
            w = target_witness(space, nodes, inds, p)
            if w:
                return w
    return None
