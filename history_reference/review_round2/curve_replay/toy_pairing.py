#!/usr/bin/env python3
"""Small-parameter real-curve backend for independent CHARE diagnostics.

E/F_523: y^2=x^3+x, #E=524, prime-order subgroup 131, embedding degree 2.
This deliberately tiny backend has no cryptographic security. It implements
curve coordinates and a reduced Tate pairing, not an exponent representation.
The pairing is t_R(P, phi(Q)), phi(x,y)=(-x, i*y), i^2=-1.

Algorithm references (accessed 2026-11-14):
https://crypto.stanford.edu/pbc/notes/elliptic/tate.html
https://crypto.stanford.edu/pbc/notes/ep/pairing.html
No production PBC performance or byte compatibility is claimed.
"""
from __future__ import annotations
from dataclasses import dataclass
import random

Q = 523
R = 131
COFACTOR = 4
FIELD_BYTES = 2
Point = tuple[int, int] | None


@dataclass(frozen=True)
class Fq2:
    a: int
    b: int = 0

    def __post_init__(self):
        object.__setattr__(self, 'a', self.a % Q)
        object.__setattr__(self, 'b', self.b % Q)

    @staticmethod
    def coerce(x):
        return x if isinstance(x, Fq2) else Fq2(x)

    def __add__(self, other):
        o = self.coerce(other)
        return Fq2(self.a + o.a, self.b + o.b)

    __radd__ = __add__

    def __neg__(self):
        return Fq2(-self.a, -self.b)

    def __sub__(self, other):
        return self + (-self.coerce(other))

    def __rsub__(self, other):
        return self.coerce(other) - self

    def __mul__(self, other):
        o = self.coerce(other)
        return Fq2(self.a*o.a-self.b*o.b, self.a*o.b+self.b*o.a)

    __rmul__ = __mul__

    def inverse(self):
        norm = (self.a*self.a+self.b*self.b) % Q
        if norm == 0:
            raise ZeroDivisionError('Zero Fq2 value')
        d = pow(norm, -1, Q)
        return Fq2(self.a*d, -self.b*d)

    def __truediv__(self, other):
        return self * self.coerce(other).inverse()

    def __pow__(self, exponent):
        if exponent < 0:
            return self.inverse() ** (-exponent)
        result, base = Fq2(1), self
        while exponent:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result

    def encode(self):
        return self.a.to_bytes(FIELD_BYTES, 'big') + self.b.to_bytes(FIELD_BYTES, 'big')


def on_curve(p: Point) -> bool:
    return p is None or (0 <= p[0] < Q and 0 <= p[1] < Q and (p[1]*p[1]-p[0]**3-p[0]) % Q == 0)


def neg(p: Point) -> Point:
    return None if p is None else (p[0], (-p[1]) % Q)


def add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x, y = p
    u, v = q
    if x == u and (y+v) % Q == 0:
        return None
    slope = ((3*x*x+1)*pow(2*y, -1, Q) if p == q else (v-y)*pow(u-x, -1, Q)) % Q
    xx = (slope*slope-x-u) % Q
    return (xx, (slope*(x-xx)-y) % Q)


def mul(k: int, p: Point) -> Point:
    # Do not reduce k modulo R here: subgroup validation must test actual R*P.
    if k < 0:
        return mul(-k, neg(p))
    out = None
    while k:
        if k & 1:
            out = add(out, p)
        p = add(p, p)
        k >>= 1
    return out


def linear_combination(terms) -> Point:
    result = None
    for coefficient, p in terms:
        result = add(result, mul(coefficient % R, p))
    return result


def subgroup(p: Point) -> bool:
    return on_curve(p) and mul(R, p) is None


def generator() -> Point:
    for x in range(Q):
        rhs = (x**3+x) % Q
        y = pow(rhs, (Q+1)//4, Q)
        if y*y % Q == rhs:
            p = mul(COFACTOR, (x, y))
            if p is not None and subgroup(p):
                return p
    raise ArithmeticError('No generator')


G = generator()


def encode_point(p: Point) -> bytes:
    if not subgroup(p):
        raise ValueError('Not a point in the declared subgroup')
    if p is None:
        return b'\x00'
    return b'\x04'+p[0].to_bytes(FIELD_BYTES, 'big')+p[1].to_bytes(FIELD_BYTES, 'big')


def decode_point(raw: bytes) -> Point:
    if raw == b'\x00':
        return None
    if len(raw) != 1+2*FIELD_BYTES or raw[0] != 4:
        raise ValueError('Noncanonical point framing')
    p = (int.from_bytes(raw[1:3], 'big'), int.from_bytes(raw[3:5], 'big'))
    if not subgroup(p) or encode_point(p) != raw:
        raise ValueError('Invalid or noncanonical subgroup point')
    return p


def decode_gt(raw: bytes) -> Fq2:
    if len(raw) != 2*FIELD_BYTES:
        raise ValueError('Invalid GT length')
    a, b = int.from_bytes(raw[:2], 'big'), int.from_bytes(raw[2:], 'big')
    if a >= Q or b >= Q:
        raise ValueError('Noncanonical GT value')
    z = Fq2(a, b)
    if z == Fq2(0) or z**R != Fq2(1):
        raise ValueError('Not in target subgroup')
    return z


def line_quotient(p: Point, q: Point, tx: Fq2, ty: Fq2) -> Fq2:
    if p is None or q is None:
        return Fq2(1)
    x, y = p
    u, v = q
    if x == u and (y+v) % Q == 0:
        return tx-x
    slope = ((3*x*x+1)*pow(2*y, -1, Q) if p == q else (v-y)*pow(u-x, -1, Q)) % Q
    numerator = ty-y-slope*(tx-x)
    total = add(p, q)
    denominator = Fq2(1) if total is None else tx-total[0]
    return numerator/denominator


def pairing(p: Point, q: Point) -> Fq2:
    if not subgroup(p) or not subgroup(q):
        raise ValueError('Pairing input outside declared subgroup')
    if p is None or q is None:
        return Fq2(1)
    tx, ty = Fq2(-q[0]), Fq2(0, q[1])
    f, v = Fq2(1), p
    for bit in bin(R)[3:]:
        f = f*f*line_quotient(v, v, tx, ty)
        v = add(v, v)
        if bit == '1':
            f = f*line_quotient(v, p, tx, ty)
            v = add(v, p)
    assert v is None
    return f**((Q*Q-1)//R)


def validate_backend() -> dict:
    assert Q % 4 == 3 and Q+1 == COFACTOR*R
    for n in [Q, R]:
        assert n > 1 and all(n % d for d in range(2, int(n**.5)+1))
    point_count = 1
    for x in range(Q):
        y2 = (x**3+x) % Q
        point_count += 1 if y2 == 0 else (2 if pow(y2, (Q-1)//2, Q) == 1 else 0)
    assert point_count == Q+1 and G is not None and subgroup(G)
    base = pairing(G, G)
    assert base != Fq2(1) and base**R == Fq2(1)
    scalars = [0, 1, 2, 3, 5, 7, 11, 17, R-1]
    for a in scalars:
        for b in scalars:
            assert pairing(mul(a, G), mul(b, G)) == base**(a*b)
    for a in range(R):
        assert decode_point(encode_point(mul(a, G))) == mul(a, G)
        assert decode_gt((base**a).encode()) == base**a
    rng = random.Random(20261114)
    for _ in range(64):
        z = Fq2(rng.randrange(Q), rng.randrange(Q))
        if z != Fq2(0):
            assert z*z.inverse() == Fq2(1)
    return {'base_field_q':Q, 'scalar_order_r':R, 'curve_point_count':point_count,
            'generator':encode_point(G).hex(), 'pairing_generator':base.encode().hex(),
            'nondegenerate':True, 'bilinearity_cases':len(scalars)**2,
            'source_encoding_roundtrips':R, 'target_encoding_roundtrips':R,
            'scope':'Small insecure diagnostic curve; actual coordinate and pairing arithmetic; not PBC/native-paper parameters.'}


if __name__ == '__main__':
    import json
    print(json.dumps(validate_backend(), indent=2))
