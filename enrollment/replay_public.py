#!/usr/bin/env python3
"""Replay the public recovery compiler without loading the fixture harness.

Reads only fixed public curve parameters and public_recovery_inputs.json.
Expected values, actor state, source scalars and fixture seeds are not inputs.
"""
from pathlib import Path
from hashlib import sha256
import json
from type_a import TypeA, Point, GT, O
from recovery_compiler import recover

HERE=Path(__file__).resolve().parent

class Ops:
    def __init__(self,b):self.b=b
    def zero(self):return O
    def plus(self,a,c):
        return self.b.add(a,c) if isinstance(a,Point) else self.b.fm(a,c)
    def times(self,n,a):
        return self.b.mul(a,n%self.b.p) if isinstance(a,Point) else self.b.fpow(a,n%self.b.p)
    def pairing(self,a,c):return self.b.pair(a,c)

def point(d):return O if d.get('infinity') else Point(int(d['x']),int(d['y']))

def main():
    b=TypeA();out=[]
    for case in json.loads((HERE/'public_recovery_inputs.json').read_text()):
        raw=case['public']
        pub={'N':raw['N'],'T':[point(x)for x in raw['T']],
             'A':[point(x)for x in raw['A']],'Gamma':point(raw['Gamma']),
             'roots':{int(t):[point(x)for x in pts]for t,pts in raw['roots'].items()}}
        value,_=recover(Ops(b),pub,case['old_nodes'],case['polynomial_ascending'],
                        case['new_node'],point(case['retained_point']),
                        tuple(point(x)for x in case['ciphertext']),b.p)
        ctx=bytes.fromhex(case['original_context_hex'])
        key=sha256(b'CHARE-coordinate-reference-H_K\0'+len(ctx).to_bytes(8,'big')+ctx+b.encode_gt(value)).digest()
        out.append({'target_id':case['target_id'],
                    'gt_sha256':sha256(b.encode_gt(value)).hexdigest(),
                    'key_sha256':sha256(key).hexdigest()})
    result={'inputs':'public curve parameters and public recovery points only','replays':out}
    (HERE/'isolated_public_replay.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'replays':len(out),'output':'isolated_public_replay.json'}))

if __name__=='__main__':main()
