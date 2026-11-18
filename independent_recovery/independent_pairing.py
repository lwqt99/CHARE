#!/usr/bin/env python3
"""R3 independent arithmetic/recovery check. No R2 Python module is imported.

Affine tuple arithmetic; full Miller line/vertical fractions; direct full final
exponent. The implementation deliberately does not use R2's Jacobian arithmetic,
denominator elimination, Frobenius final exponent, or recovery compiler.
It is a functional cross-check, not a native-Go reproduction or security proof.
"""
import argparse
import json
import time
from pathlib import Path
from hashlib import sha256
from sympy import isprime

HERE = Path(__file__).resolve().parent
DEFAULT_INPUT = HERE / 'public_inputs'
DEFAULT_OUTPUT = HERE / 'independent_pairing_results.json'


class Curve:
    def __init__(self, record):
        self.p, self.q = int(record['p']), int(record['q'])
        self.one = (1, 0)
        self.width = (self.q.bit_length() + 7) // 8
        self.pairing_count = 0
        self.vertical_count = 0

    def add(self, A, B):
        if A is None: return B
        if B is None: return A
        q = self.q
        x, y = A; u, v = B
        if x == u and (y + v) % q == 0: return None
        s = ((3*x*x + 1) * pow(2*y, -1, q) if A == B
             else (v-y) * pow((u-x) % q, -1, q)) % q
        w = (s*s-x-u) % q
        return w, (s*(x-w)-y) % q

    def mul(self, A, n):
        if n < 0:
            A = None if A is None else (A[0], -A[1] % self.q)
            n = -n
        R = None
        # Right-to-left integer multiplication, without reduction modulo p.
        while n:
            if n & 1: R = self.add(R, A)
            A = self.add(A, A)
            n >>= 1
        return R

    def fm(self, A, B):
        a,b=A; c,d=B; q=self.q
        return (a*c-b*d) % q, (a*d+b*c) % q

    def inverse(self, A):
        a,b=A
        t=pow((a*a+b*b) % self.q, -1, self.q)
        return a*t % self.q, -b*t % self.q

    def power(self, A, n):
        if n < 0: A,n=self.inverse(A),-n
        R=self.one
        while n:
            if n & 1: R=self.fm(R,A)
            A=self.fm(A,A); n >>= 1
        return R

    def line_fraction(self, A, B, Q):
        """Return line(distortion Q), vertical(A+B)(distortion Q), A+B."""
        if A is None: return self.one,self.one,B
        if B is None: return self.one,self.one,A
        q=self.q; x,y=A; u,v=B; zx,zy=-Q[0] % q,Q[1]
        C=self.add(A,B)
        if C is None:
            return ((zx-x) % q,0),self.one,None
        s=((3*x*x+1)*pow(2*y,-1,q) if A==B
           else (v-y)*pow((u-x) % q,-1,q)) % q
        numerator=((-y-s*(zx-x)) % q,zy)
        denominator=((zx-C[0]) % q,0)
        assert numerator != (0,0) and denominator != (0,0)
        self.vertical_count += 1
        return numerator,denominator,C

    def pair(self, A, Q):
        self.pairing_count += 1
        if A is None or Q is None: return self.one
        R=A; num=den=self.one
        for b in bin(self.p)[3:]:
            l,v,R=self.line_fraction(R,R,Q)
            num=self.fm(self.fm(num,num),l)
            den=self.fm(self.fm(den,den),v)
            if b == '1':
                l,v,R=self.line_fraction(R,A,Q)
                num=self.fm(num,l); den=self.fm(den,v)
        assert R is None
        # Full exponent, independently of the denominator-elimination identity.
        return self.power(self.fm(num,self.inverse(den)),(self.q*self.q-1)//self.p)

    def encode_gt(self, A):
        return b''.join(v.to_bytes(self.width,'big') for v in A)

    def valid(self, A):
        if A is None: return True
        x,y=A
        return (0<=x<self.q and 0<=y<self.q and
                (y*y-x*x*x-x) % self.q==0 and self.mul(A,self.p) is None)


def point(d):
    return None if d.get('infinity') else (int(d['x']),int(d['y']))


def evaluate(f,x,p):
    r=0
    for c in reversed(f): r=(r*x+c) % p
    return r


def vanishing(nodes,p):
    f=[1]
    for t in nodes:
        g=[0]*(len(f)+1)
        for i,c in enumerate(f):
            g[i]=(g[i]-t*c) % p
            g[i+1]=(g[i+1]+c) % p
        f=g
    return f


def synthetic_quotient(f,t,p):
    # Quotient of (f(X)-f(t))/(X-t), computed by Horner's synthetic division.
    b=f[-1] % p; descending=[b]
    for c in reversed(f[1:-1]):
        b=(c+t*b) % p; descending.append(b)
    return list(reversed(descending))


def recover_independently(curve,case):
    p=curve.p; raw=case['public']; I=case['old_nodes']; a=case['new_node']
    f=case['polynomial_ascending']; n=len(I)+1; N=raw['N']
    Q=vanishing(I,p)
    zeta=evaluate(Q,a,p)*pow(evaluate(f,a,p),-1,p) % p
    q=[((zeta*f[i] if i<len(f) else 0)-(Q[i] if i<len(Q) else 0)) % p
       for i in range(max(len(f),len(Q)))]
    assert q[-1]==p-1 and evaluate(q,a,p)==0
    W=None
    for coefficient,T in zip(q,raw['T']): W=curve.add(W,curve.mul(point(T),coefficient))
    R=point(raw['Gamma'])
    for i in range(n-1):
        R=curve.add(R,curve.mul(point(raw['A'][N-n+i]),-q[i]))
    for t in I+[a]:
        quotient=synthetic_quotient(q,t,p)
        for c,projection in zip(quotient,raw['roots'][str(t)]):
            R=curve.add(R,curve.mul(point(projection),-c))
    R=curve.add(R,curve.mul(point(case['retained_point']),-zeta))
    C0,C1=map(point,case['ciphertext'])
    return curve.fm(curve.pair(C0,R),curve.pair(C1,W))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, default=DEFAULT_INPUT,
                        help='Directory containing the three public JSON inputs (default: public_inputs next to this script)')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT,
                        help='Result JSON path (default: independent_pairing_results.json next to this script)')
    args = parser.parse_args()
    input_dir = args.input_dir.resolve()
    output = args.output.resolve()
    start=time.monotonic()
    params=json.loads((input_dir/'parameters.json').read_text())
    cases=json.loads((input_dir/'public_recovery_inputs.json').read_text())
    curve=Curve(params); checks=[]
    def check(name,ok,**extra):
        assert ok,name
        checks.append({'name':name,'status':'PASS',**extra})
    check('parameter arithmetic',curve.q==12*int(params['ell'])*curve.p-1 and curve.q%4==3)
    check('probable-prime screening',bool(isprime(curve.p) and isprime(curve.q)),
          qualification='SymPy BPSW screening; this is not a primality certificate')
    all_points={}
    for case in cases:
        raw=case['public']
        pts=raw['T']+raw['A']+[raw['Gamma'],case['retained_point']]+case['ciphertext']
        for ps in raw['roots'].values(): pts+=ps
        for P in pts: all_points[str(P)]=point(P)
    check('all distinct public inputs are curve/subgroup points',all(curve.valid(P) for P in all_points.values()),count=len(all_points))
    g=point(cases[0]['public']['T'][0])
    E=curve.pair(g,g)
    check('nondegenerate subgroup pairing',E!=curve.one and curve.power(E,curve.p)==curve.one)
    for a,b in [(2,3),(7,11)]:
        P,Q=curve.mul(g,a),curve.mul(g,b)
        pair=curve.pair(P,Q)
        check('bilinearity %s,%s'%(a,b),pair==curve.power(E,a*b))
        check('symmetry %s,%s'%(a,b),pair==curve.pair(Q,P))
    results=[]
    for case in cases:
        V=recover_independently(curve,case)
        ctx=bytes.fromhex(case['original_context_hex'])
        enc=curve.encode_gt(V)
        key=sha256(b'CHARE-coordinate-reference-H_K\0'+len(ctx).to_bytes(8,'big')+ctx+enc).digest()
        results.append({'target_id':case['target_id'],'gt_sha256':sha256(enc).hexdigest(),
                        'key_sha256':sha256(key).hexdigest()})
    # Expected hashes are loaded only after all recovered outputs have been made.
    expected=json.loads((input_dir/'expected_recovery_hashes.json').read_text())
    for row in results:
        wanted=expected[row['target_id']]
        check('public-only recovery '+row['target_id'],
              row['gt_sha256']==wanted['expected_gt_sha256'] and
              row['key_sha256']==wanted['expected_key_sha256'])
    result={'status':'PASS','scope':'Independent public-coordinate recovery and full-denominator pairing cross-check',
            'imports_from_R2':False,'checks':checks,'recoveries':results,
            'pairing_calls':curve.pairing_count,'included_vertical_denominators':curve.vertical_count,
            'wall_seconds':time.monotonic()-start,'timing_meaning':'Execution duration only, not paper/native latency',
            'limitations':['No native Go/PBC benchmark reproduction','No formal verification','No primality certificate','Four fixed public recovery cases, not exhaustive protocol testing']}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'checks':len(checks),'recoveries':len(results),'wall_seconds':result['wall_seconds']}))


if __name__=='__main__': main()
