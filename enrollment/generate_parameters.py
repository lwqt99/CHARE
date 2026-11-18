#!/usr/bin/env python3
"""Generate the fixed reference Type-A parameters; SymPy is needed only here."""
from hashlib import sha256
from pathlib import Path
import json
import random
from sympy import isprime, nextprime

seed=b'CHARE-round2-coordinate-pairing-parameters-20261109'
p=int(nextprime((int.from_bytes(sha256(seed+b':p').digest(),'big') | (1<<255) | 1)))
assert p.bit_length()==256
rng=random.Random(int.from_bytes(sha256(seed+b':q').digest(),'big'))
low=((1<<1535)+12*p-1)//(12*p)
high=((1<<1536)-1)//(12*p)
tries=0
while True:
    tries+=1
    ell=rng.randrange(low,high+1)
    q=12*ell*p-1
    if isprime(q):
        break
assert isprime(p) and q.bit_length()==1536 and q%4==3
assert (q+1)%p==0
out={'profile':'supersingular Type-A reference, affine coordinate backend',
     'curve':'y^2 = x^3 + x over F_q',
     'embedding_extension':'F_q[i] / (i^2 + 1)',
     'p':str(p),'q':str(q),'ell':str(ell),'cofactor':str((q+1)//p),
     'p_bits':p.bit_length(),'q_bits':q.bit_length(),
     'parameter_relation':'q = 12*ell*p - 1',
     'generation_seed':seed.decode(),'prime_candidates_tested':tries,
     'primality_checked_by':'SymPy 1.14.0 isprime (reproducible probable-prime screening; no primality certificate)',
     'security_level':'No concrete security-level claim or timing comparison is made.'}
dest=Path(__file__).with_name('parameters.json')
dest.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'parameters':str(dest),'p_bits':p.bit_length(),'q_bits':q.bit_length(),'prime_candidates_tested':tries}),flush=True)
