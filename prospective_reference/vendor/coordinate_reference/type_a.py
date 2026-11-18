"""Coordinate-only supersingular Type-A reference backend.

E/F_q: y^2=x^3+x, q=3 mod 4, prime subgroup order p | q+1.
e(P,Q)=Tate_p(P,(-x_Q, i*y_Q)) in F_{q^2}, followed by reduction.
Point stores affine coordinates only; GT stores its two F_q coordinates only.
No element carries a generator exponent, symbolic label, or source expression.

Primary references:
  https://crypto.stanford.edu/pbc/manual/ch08s03.html
  https://crypto.stanford.edu/pbc/thesis.pdf (Miller arithmetic, Type-A curves)
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import random


@dataclass(frozen=True, slots=True)
class Point:
    x: int | None
    y: int | None


@dataclass(frozen=True, slots=True)
class GT:
    a: int
    b: int


O = Point(None, None)


class TypeA:
    def __init__(self, parameter_path=None):
        path=Path(parameter_path) if parameter_path else Path(__file__).with_name('parameters.json')
        self.parameter_record=json.loads(path.read_text())
        self.p=int(self.parameter_record['p'])
        self.q=int(self.parameter_record['q'])
        self.cofactor=(self.q+1)//self.p
        self.width=(self.q.bit_length()+7)//8
        self.one=GT(1,0)
        assert self.q%4==3 and (self.q+1)%self.p==0

    def on_curve(self,P):
        if P==O: return True
        if P.x is None or P.y is None: return False
        return (0<=P.x<self.q and 0<=P.y<self.q and
                (P.y*P.y-P.x*P.x*P.x-P.x)%self.q==0)

    def neg(self,P):
        return P if P==O else Point(P.x,(-P.y)%self.q)

    def add(self,P,Q):
        if P==O:return Q
        if Q==O:return P
        q=self.q
        if P.x==Q.x:
            if (P.y+Q.y)%q==0:return O
            slope=(3*P.x*P.x+1)*pow(2*P.y,-1,q)%q
        else:
            slope=(Q.y-P.y)*pow((Q.x-P.x)%q,-1,q)%q
        x=(slope*slope-P.x-Q.x)%q
        return Point(x,(slope*(P.x-x)-P.y)%q)

    def _j_double(self,P):
        x,y,z=P
        if z==0 or y==0:return (0,1,0)
        q=self.q
        a=x*x%q; b=y*y%q; c=b*b%q
        d=2*((x+b)*(x+b)-a-c)%q
        z2=z*z%q
        e=(3*a+z2*z2)%q
        f=e*e%q
        x3=(f-2*d)%q
        y3=(e*(d-x3)-8*c)%q
        z3=2*y*z%q
        return (x3,y3,z3)

    def _j_add_affine(self,P,Q):
        if Q==O:return P
        x,y,z=P
        if z==0:return (Q.x,Q.y,1)
        q=self.q
        z2=z*z%q
        u2=Q.x*z2%q
        s2=Q.y*z*z2%q
        h=(u2-x)%q
        r=2*(s2-y)%q
        if h==0:
            return self._j_double(P) if r==0 else (0,1,0)
        hh=h*h%q; i=4*hh%q; j=h*i%q; v=x*i%q
        x3=(r*r-j-2*v)%q
        y3=(r*(v-x3)-2*y*j)%q
        z3=((z+h)*(z+h)-z2-hh)%q
        return (x3,y3,z3)

    def mul(self,P,n):
        # Do not reduce n modulo p: subgroup/cofactor tests require the actual
        # integer multiplication, including p*P and ((q+1)/p)*P.
        if n<0:return self.mul(self.neg(P),-n)
        if n==0 or P==O:return O
        R=(0,1,0)
        for bit in bin(n)[2:]:
            R=self._j_double(R)
            if bit=='1':R=self._j_add_affine(R,P)
        x,y,z=R
        if z==0:return O
        zi=pow(z,-1,self.q)
        return Point(x*zi*zi%self.q,y*zi*zi*zi%self.q)

    def sum_points(self,points):
        out=O
        for P in points:out=self.add(out,P)
        return out

    def fm(self,x,y):
        q=self.q
        return GT((x.a*y.a-x.b*y.b)%q,(x.a*y.b+x.b*y.a)%q)

    def fs(self,x):
        q=self.q
        return GT((x.a*x.a-x.b*x.b)%q,2*x.a*x.b%q)

    def fi(self,x):
        q=self.q
        inv=pow((x.a*x.a+x.b*x.b)%q,-1,q)
        return GT(x.a*inv%q,-x.b*inv%q)

    def fpow(self,x,n):
        if n<0:return self.fpow(self.fi(x),-n)
        out=self.one
        for bit in bin(n)[2:]:
            out=self.fs(out)
            if bit=='1':out=self.fm(out,x)
        return out

    def _miller_step(self,R,S,Q):
        """Evaluate the line through R,S at distortion(Q), returning R+S.

        Every omitted vertical denominator lies in F_q^*, and reduction raises
        it to an exponent divisible by q-1. The final exponent removes it.
        """
        if R==O:return self.one,S
        if S==O:return self.one,R
        q=self.q
        if R.x==S.x:
            if (R.y+S.y)%q==0:
                return GT((-Q.x-R.x)%q,0),O
            slope=(3*R.x*R.x+1)*pow(2*R.y,-1,q)%q
        else:
            slope=(S.y-R.y)*pow((S.x-R.x)%q,-1,q)%q
        x=(slope*slope-R.x-S.x)%q
        result=Point(x,(slope*(R.x-x)-R.y)%q)
        # Distortion(Q)=(-Q.x, i*Q.y), so l(Q)=i*Q.y-R.y-slope*(-Q.x-R.x).
        line=GT((slope*(Q.x+R.x)-R.y)%q,Q.y)
        assert line!=GT(0,0)
        return line,result

    def pair(self,P,Q):
        if P==O or Q==O:return self.one
        assert self.on_curve(P) and self.on_curve(Q)
        R=P
        f=self.one
        for bit in bin(self.p)[3:]:
            line,R=self._miller_step(R,R,Q)
            f=self.fm(self.fs(f),line)
            if bit=='1':
                line,R=self._miller_step(R,P,Q)
                f=self.fm(f,line)
        assert R==O,'Miller input is outside the p subgroup'
        # f^(q-1)=conjugate(f)/f, then power by (q+1)/p.
        fq=GT(f.a,(-f.b)%self.q)
        reduced=self.fpow(self.fm(fq,self.fi(f)),self.cofactor)
        return reduced

    def generator(self,domain=b'CHARE-TypeA-reference-generator'):
        rng=random.Random(int.from_bytes(sha256(domain).digest(),'big'))
        while True:
            x=rng.randrange(self.q)
            rhs=(x*x*x+x)%self.q
            if rhs and pow(rhs,(self.q-1)//2,self.q)==1:
                y=pow(rhs,(self.q+1)//4,self.q)
                if y&1:y=self.q-y
                P=self.mul(Point(x,y),self.cofactor)
                if P!=O:
                    assert self.on_curve(P) and self.mul(P,self.p)==O
                    return P

    def encode_point(self,P):
        if P==O:return bytes(1+2*self.width)
        assert self.on_curve(P)
        return b'\x04'+P.x.to_bytes(self.width,'big')+P.y.to_bytes(self.width,'big')

    def decode_point(self,data):
        if len(data)!=1+2*self.width:raise ValueError('Wrong point encoding length')
        if data==bytes(len(data)):return O
        if data[0]!=4:raise ValueError('Unsupported point prefix')
        P=Point(int.from_bytes(data[1:1+self.width],'big'),int.from_bytes(data[1+self.width:],'big'))
        if not self.on_curve(P) or self.mul(P,self.p)!=O:raise ValueError('Invalid subgroup point')
        return P

    def encode_gt(self,x):
        return x.a.to_bytes(self.width,'big')+x.b.to_bytes(self.width,'big')

    def public_point(self,P):
        return {'infinity':True} if P==O else {'x':str(P.x),'y':str(P.y)}

    def public_gt(self,x):
        return {'a':str(x.a),'b':str(x.b)}


def backend_selftest(backend):
    b=backend
    g=b.generator()
    checks=[]
    def record(name,ok):
        assert ok,name
        checks.append({'check':name,'status':'PASS'})
    record('coordinate-only element data',Point.__slots__==('x','y') and GT.__slots__==('a','b'))
    record('nonidentity subgroup generator',g!=O and b.on_curve(g) and b.mul(g,b.p)==O)
    record('actual scalar multiplication',b.mul(g,3)==b.add(g,b.add(g,g)))
    record('source identity and inverse',b.add(g,b.neg(g))==O and b.mul(g,0)==O)
    record('canonical point round trip',b.decode_point(b.encode_point(g))==g and b.decode_point(b.encode_point(O))==O)
    e=b.pair(g,g)
    record('pairing nondegeneracy',e!=b.one)
    record('target subgroup order',b.fpow(e,b.p)==b.one)
    record('pairing zero arguments',b.pair(O,g)==b.one and b.pair(g,O)==b.one)
    for a,c in [(7,11),(103,211)]:
        P,Q=b.mul(g,a),b.mul(g,c)
        pq=b.pair(P,Q)
        record(f'bilinearity scalars {a},{c}',pq==b.fpow(e,a*c))
        record(f'symmetry scalars {a},{c}',pq==b.pair(Q,P))
    record('target inverse',b.fm(e,b.fi(e))==b.one)
    record('pairing source inverse',b.pair(b.neg(g),g)==b.fi(e))
    return {'status':'PASS','p_bits':b.p.bit_length(),'q_bits':b.q.bit_length(),
            'generator':b.public_point(g),'base_pairing':b.public_gt(e),'checks':checks}


if __name__=='__main__':
    b=TypeA()
    result=backend_selftest(b)
    path=Path(__file__).with_name('backend_selftest.json')
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'checks':len(result['checks']),'output':str(path)}))
