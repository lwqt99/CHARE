#!/usr/bin/env python3
"""Coordinate pairing executions; attack inputs are public material only."""
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
from pathlib import Path
import json
import random
from type_a import TypeA, Point, GT, O, backend_selftest
from recovery_compiler import recover, evaluate, vanishing, divide, audit_enrollment_with_plans

HERE=Path(__file__).parent

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def digest(data):return sha256(data).hexdigest()
def kdf(b,ctx,x):return sha256(b'CHARE-coordinate-reference-H_K\0'+len(ctx).to_bytes(8,'big')+ctx+b.encode_gt(x)).digest()

def rref(rows,p):
    a=[[x%p for x in row]for row in rows]
    if not a:return [],[]
    d=0;pivots=[]
    for c in range(len(a[0])):
        j=next((j for j in range(d,len(a))if a[j][c]),None)
        if j is None:continue
        a[d],a[j]=a[j],a[d]
        z=pow(a[d][c],-1,p);a[d]=[x*z%p for x in a[d]]
        for j in range(len(a)):
            if j!=d and a[j][c]:
                z=a[j][c];a[j]=[(x-z*y)%p for x,y in zip(a[j],a[d])]
        pivots.append(c);d+=1
        if d==len(a):break
    return a[:d],pivots

def rank(rows,p):return len(rref(rows,p)[0])
def nullspace(rows,width,p):
    a,pivots=rref(rows,p);out=[]
    for free in range(width):
        if free in pivots:continue
        v=[0]*width;v[free]=1
        for i,c in enumerate(pivots):v[c]=-a[i][free]%p
        out.append(v)
    return out

def target_audit(nodes,full_rows,p):
    """Independent original target criterion for every nonempty subset."""
    rows=[[row[t-1]%p for t in nodes]for row in full_rows];bad=[];total=0
    for size in range(1,len(nodes)+1):
        for inside in combinations(range(len(nodes)),size):
            total+=1;J=[nodes[i]for i in inside];gamma=[]
            for t in J:
                den=1
                for u in J:
                    if t!=u:den=den*(t-u)%p
                gamma.append(pow(den,-1,p))
            functional=[sum(g*row[j]for g,j in zip(gamma,inside))%p for row in rows]
            outside=[[row[j]for row in rows]for j in range(len(nodes))if j not in inside]
            if rank(outside+[functional],p)!=rank(outside,p):bad.append(J)
    return {'active_nodes':list(nodes),'direction_rank':rank(rows,p),'targets_checked':total,
            'protected_targets':total-len(bad),'recoverable_targets':bad,
            'status':'PROTECTED' if not bad else 'RECOVERABLE'}

class PublicOps:
    """Adapter for the unchanged prior recovery compiler; no private actor state."""
    __slots__=('backend',)
    def __init__(self,b):self.backend=b
    def zero(self,kind='G'):return O if kind=='G' else self.backend.one
    def plus(self,A,B):
        if isinstance(A,Point)and isinstance(B,Point):return self.backend.add(A,B)
        if isinstance(A,GT)and isinstance(B,GT):return self.backend.fm(A,B)
        raise TypeError('Group mismatch')
    def times(self,c,A):
        if isinstance(A,Point):return self.backend.mul(A,c%self.backend.p)
        if isinstance(A,GT):return self.backend.fpow(A,c%self.backend.p)
        raise TypeError('Unknown group')
    def pairing(self,A,B):return self.backend.pair(A,B)

@dataclass(frozen=True)
class Target:
    target_id:str
    nodes:tuple
    C0:Point
    C1:Point
    context:bytes

class Harness:
    def __init__(self,b,seed,name):
        self.b=b;self.p=b.p;self.N=6;self.seed=seed;self.name=name
        self.rng=random.Random(int.from_bytes(sha256(seed.encode()).digest(),'big'))
        self.events=[];self.active=[];self.holders={};self.completed=[];self.plans={}
        self.expected={};self.targets=[];self.points={};self.pad_ids=set();self.evidence=[]
        self.public=self.setup()
        self.setup_id=digest(canonical(self.serialize_public(False)))
        self.core_ids={t:f'{self.setup_id[:16]}/core/slot-{t}/generation-0'for t in range(1,7)}
        self.event('setup',capacity=6,nodes=list(range(1,7)),setup_id=self.setup_id)

    def event(self,kind,**kw):self.events.append({'sequence':len(self.events)+1,'event':kind,**kw})
    def point_ref(self,P):
        key=digest(self.b.encode_point(P));self.points.setdefault(key,self.b.public_point(P));return key
    def setup(self):
        b=self.b;p=self.p;g=b.generator()
        a,beta,theta=[self.rng.randrange(1,p)for _ in range(3)]
        alpha=self.rng.randrange(p);tau=self.rng.randrange(self.N+1,p)
        powers=[pow(tau,d,p)for d in range(self.N)];h=b.mul(g,theta)
        # Generating scalars remain local to this function. Future roots use
        # only public T coordinates and the newly born holder's own core.
        return {'N':self.N,'nodes':list(range(1,7)),'g':g,'h':h,
            'Y':[b.mul(g,a*x%p)for x in powers],
            'W':{t:b.mul(g,beta*pow((tau-t)%p,-1,p)%p)for t in range(1,7)},
            'T':[b.mul(h,x)for x in powers],
            'A':[b.mul(h,a*x%p)for x in powers[:-1]],
            'B':[b.mul(h,beta*x%p)for x in powers[:-1]],
            'Gamma':b.mul(h,(alpha+a*powers[-1])%p),
            'Z':b.fpow(b.pair(g,h),alpha),'roots':{},'V':{}}

    def serialize_public(self,roots=True):
        b=self.b;x=self.public
        d={'N':x['N'],'nodes':x['nodes'],'g':b.public_point(x['g']),'h':b.public_point(x['h']),
           'Gamma':b.public_point(x['Gamma']),'Z':b.public_gt(x['Z'])}
        for name in ['Y','T','A','B']:d[name]=[b.public_point(P)for P in x[name]]
        d['W']={str(t):b.public_point(P)for t,P in x['W'].items()}
        if roots:
            d['roots']={str(t):[b.public_point(P)for P in pts]for t,pts in x['roots'].items()}
            d['V']={str(t):b.public_point(P)for t,P in x['V'].items()}
        return d

    def enroll(self,t,decision,bypass_for_counterexample=False):
        assert t in self.core_ids and t not in self.active
        if self.active and not self.enrollment_audit(t,True):
            if not bypass_for_counterexample:
                raise ValueError('Enrollment violates the retained and pending directions')
        before=list(self.active);v=self.rng.randrange(self.p)
        self.holders[t]={'v':v,'source_id':self.core_ids[t],'pads':{}}
        V=self.b.mul(self.public['g'],v);projections=[]
        for k in range(self.N-1):
            base=self.b.add(self.public['T'][k+1],self.b.neg(self.b.mul(self.public['T'][k],t)))
            P=self.b.mul(base,v)
            assert self.b.pair(V,base)==self.b.pair(self.public['g'],P)
            projections.append(P)
        self.public['V'][t]=V;self.public['roots'][t]=projections
        self.active.append(t);self.active.sort()
        self.event('honest_core_birth_and_enrollment',node=t,core_source_id=self.core_ids[t],
            active_before=before,active_after=list(self.active),core_sampled_at_this_event=True,
            projection_equations_checked=self.N-1,public_root=self.point_ref(V),
            projection_points=[self.point_ref(P)for P in projections],admission_decision=decision)

    def rows(self):return [list(x['row'])for x in self.completed]
    def pending_rows(self):return [list(x['row'])for x in self.plans.values()if x['status']=='pending']
    def enrollment_audit(self,t,pending=True):
        actual=self.rows();planned=self.pending_rows()if pending else []
        assert target_audit(self.active,actual+planned,self.p)['status']=='PROTECTED'
        a=[[row[x-1]for x in self.active]for row in actual]
        q=[[row[x-1]for x in self.active]for row in planned]
        result=audit_enrollment_with_plans(self.active,a,q,[t],self.p)
        self.event('enrollment_audit',candidate=t,includes_pending=pending,
                   current_rows=len(a),pending_rows=len(q),**result)
        return t in result['admissible_nodes']

    def reserve(self,f,label):
        nodes=list(self.active);pid=f'{self.name}/plan-{len(self.plans)+1}'
        row=[0]*self.N
        for t in nodes:row[t-1]=evaluate(f,t,self.p)
        if target_audit(nodes,self.rows()+self.pending_rows()+[row],self.p)['status']!='PROTECTED':
            raise ValueError('The frozen direction violates a current canonical target')
        edges=list(zip(nodes[:-1],nodes[1:]));pads={};ids={}
        for a,c in edges:
            sid=f'{pid}/direction-0/edge-{a}-{c}/pad'
            assert sid not in self.pad_ids;self.pad_ids.add(sid)
            value=self.rng.randrange(self.p);pads[(a,c)]=value;ids[(a,c)]=sid
            self.holders[a]['pads'][sid]=value;self.holders[c]['pads'][sid]=value
        self.plans[pid]={'id':pid,'nodes':nodes,'row':row,'f':list(f),'edges':edges,
                        'pads':pads,'ids':ids,'points':{},'status':'pending'}
        self.event('plan_frozen_and_pads_installed',plan_id=pid,label=label,participants=nodes,
            core_sources=[self.core_ids[t]for t in nodes],coefficient_row=row,
            polynomial_ascending=list(f),graph_edges=edges,pad_source_ids=list(ids.values()),
            endpoint_installations=2*len(edges),independent_full_field_pads=True)
        return pid

    def publish(self,pid,t):
        x=self.plans[pid]
        assert x['status']=='pending'and t in x['nodes']and t not in x['points']
        value=x['row'][t-1]*self.holders[t]['v']
        for (a,c),pad in x['pads'].items():
            if t==a:value+=pad
            if t==c:value-=pad
        P=self.b.mul(self.public['h'],value%self.p);x['points'][t]=P
        seen=sorted(x['points'])
        constraints=[[int(i==a)-int(i==c)for i in seen]for a,c in x['edges']]
        pure=[]
        for coefficients in nullspace(constraints,len(seen),self.p):
            row=[0]*self.N
            for z,i in zip(coefficients,seen):row[i-1]=z*x['row'][i-1]%self.p
            pure.append(row)
        self.event('contribution_visible',plan_id=pid,node=t,core_source_id=self.core_ids[t],
            visible_nodes=seen,point=self.point_ref(P),prefix_core_capability_rank=rank(pure,self.p),
            original_pad_source_ids=[x['ids'][edge]for edge in x['edges']if t in edge])
        if len(seen)==len(x['nodes']):
            L=self.b.sum_points(x['points'][i]for i in x['nodes'])
            expected=self.b.mul(self.public['h'],sum(x['row'][i-1]*self.holders[i]['v']for i in x['nodes'])%self.p)
            assert L==expected
            x['aggregate']=L;x['status']='complete'
            self.completed.append({'plan_id':pid,'row':tuple(x['row']),'point':L})
            self.event('plan_completed',plan_id=pid,aggregate=self.point_ref(L),coefficient_row=x['row'],
                       pad_cancellation_equal=True,original_partials=[self.point_ref(x['points'][i])for i in x['nodes']])
        return P

    def complete(self,pid):
        x=self.plans[pid]
        for t in x['nodes']:
            if t not in x['points']:self.publish(pid,t)
        return x['aggregate']

    def target(self,nodes,label):
        nodes=list(nodes);assert set(nodes)<=set(self.active)
        n=len(nodes);s=self.rng.randrange(self.p)
        P=self.b.add(self.public['Y'][self.N-n],self.b.sum_points(self.public['V'][t]for t in nodes))
        C0=self.b.mul(self.public['g'],s);C1=self.b.mul(P,s)
        expected=self.b.fpow(self.public['Z'],s)
        ctx=canonical({'domain':'CHARE-coordinate-reference-empty-policy-KEM-v1',
          'setup_id':self.setup_id,'instance':label,'target_sequence':len(self.targets)+1,
          'snapshot':list(self.active),'J':nodes,'policy':[],'weights':[],
          'core_source_ids':[self.core_ids[t]for t in nodes],
          'C0':self.b.encode_point(C0).hex(),'C1':self.b.encode_point(C1).hex()})
        tid=digest(ctx);target=Target(tid,tuple(nodes),C0,C1,ctx)
        self.targets.append(target);self.expected[tid]=expected
        self.event('original_ciphertext_created',target_id=tid,label=label,selected_nodes=nodes,
             source_ids=[self.core_ids[t]for t in nodes],C0=self.point_ref(C0),C1=self.point_ref(C1),
             context_sha256=digest(ctx))
        # Independent honest receiver computation checks the actual construction.
        i=nodes[0];qi=vanishing([t for t in nodes if t!=i],self.p)
        Ri=self.b.sum_points(self.b.mul(self.public['T'][d],c)for d,c in enumerate(qi))
        Gi=self.public['Gamma']
        for d,c in enumerate(qi[:-1]):Gi=self.b.add(Gi,self.b.mul(self.public['A'][self.N-n+d],c))
        Hi=O
        for t in nodes:
            if t==i:continue
            quotient,remainder=divide(qi,[-t,1],self.p);assert remainder==[0]
            for d,c in enumerate(quotient):Hi=self.b.add(Hi,self.b.mul(self.public['roots'][t][d],c))
        correction=self.b.add(Gi,self.b.add(Hi,self.b.mul(Ri,self.holders[i]['v'])))
        value=self.b.fm(self.b.pair(C0,correction),self.b.fi(self.b.pair(C1,Ri)))
        assert value==expected
        self.event('honest_decapsulation_checked',target_id=tid,recipient=i,original_input_equal=True)
        return target

    def audit(self,stage):
        result=target_audit(self.active,self.rows(),self.p)
        self.event('all_subset_target_audit',stage=stage,**result);return result

    def attack(self,target,L,purpose):
        # The original compiler receives no holder/pad/setup/encapsulation scalar.
        answer,witness=recover(PublicOps(self.b),self.public,[1,2,3,4],[1],5,L,
                               (target.C0,target.C1),self.p)
        expected=self.expected[target.target_id]
        assert answer==expected
        original_key=kdf(self.b,target.context,expected)
        assert kdf(self.b,target.context,answer)==original_key
        assert kdf(self.b,target.context+b'/different-context',answer)!=original_key
        self.evidence.append({'purpose':purpose,'seed':self.seed,'trace':self.name,
             'public':self.serialize_public(),'old_nodes':[1,2,3,4],'polynomial_ascending':[1],
             'new_node':5,'retained_point':self.b.public_point(L),
             'ciphertext':[self.b.public_point(target.C0),self.b.public_point(target.C1)],
             'original_context_hex':target.context.hex(),'target_id':target.target_id,
             'expected_gt_sha256':digest(self.b.encode_gt(expected)),
             'expected_key_sha256':digest(original_key),'witness':witness})
        self.event('public_recovery_executed',purpose=purpose,target_id=target.target_id,
            inputs=['public parameters','original root projections','retained aggregate',
                    'old coefficient polynomial','original ciphertext','original context'],
            actual_gt_equal=True,same_context_kdf_equal=True,different_context_changes_key=True,
            witness=witness,recovered_gt_sha256=digest(self.b.encode_gt(answer)),
            holder_or_pad_scalars_supplied=False,setup_or_encapsulation_scalars_supplied=False)
        return {'target_id':target.target_id,'actual_gt_equal':True,'same_context_kdf_equal':True}

    def finish(self,summary):
        return {'trace':self.name,'seed':self.seed,'summary':summary,'events':self.events,
          'retained_public_points':self.points,'original_targets':[{'target_id':t.target_id,
          'nodes':list(t.nodes),'context_sha256':digest(t.context)}for t in self.targets],
          'completed_plans':len(self.completed),'pending_plans':sum(x['status']=='pending'for x in self.plans.values()),
          'physical_core_births':len(self.holders),'unique_pad_sources':len(self.pad_ids),'status':'PASS'}

def initial_holders(h):
    for t in range(1,5):h.enroll(t,'initial protected core')

def safe_trace(b,seed):
    h=Harness(b,seed,'safe-4-to-5-to-6');initial_holders(h)
    old=h.target([1,2],'old-two-node-target')
    pid=h.reserve(vanishing([5,6],h.p),'initial reserved-root direction')
    h.publish(pid,1);h.publish(pid,2)
    assert h.enrollment_audit(5,True)
    L0=h.complete(pid);stages=[h.audit('four active')]
    assert stages[-1]['status']=='PROTECTED'and stages[-1]['direction_rank']==1
    crossing=h.reserve(vanishing([5,6],h.p),'reserved plan spanning enrollment')
    h.publish(crossing,1);h.publish(crossing,2)
    original_partials=[h.point_ref(h.plans[crossing]['points'][t])for t in [1,2]]
    assert h.enrollment_audit(5,True)
    h.enroll(5,'admitted: retained and pending polynomials vanish at 5')
    retained_five=h.target([1,2,3,4,5],'five-node-target-before-old-plan-completion')
    crossing_output=h.complete(crossing)
    assert crossing_output==L0
    assert original_partials==[h.point_ref(h.plans[crossing]['points'][t])for t in [1,2]]
    h.event('safe_old_plan_completed_after_enrollment',plan_id=crossing,
        target_id=retained_five.target_id,original_partials_unchanged=True,
        original_pad_sources_retained=True,aggregate_matches_old_direction=True)
    L1=h.complete(h.reserve(vanishing([6],h.p),'new direction after node 5'))
    stages.append(h.audit('five active'))
    assert stages[-1]['status']=='PROTECTED'and stages[-1]['direction_rank']==2
    h.target([1,2,3,4,5],'five-node-target')
    assert h.enrollment_audit(6,True)
    h.enroll(6,'admitted: retained and pending polynomials vanish at 6')
    L2=h.complete(h.reserve([1],'new direction after node 6'))
    stages.append(h.audit('six active'))
    assert stages[-1]['status']=='PROTECTED'and stages[-1]['direction_rank']==3
    h.target([1,2,3,4,5,6],'six-node-target')
    X=b.add(L1,b.mul(L2,6));X2=b.add(b.add(L0,b.mul(L1,5)),b.mul(X,6))
    assert X==b.mul(h.public['h'],sum(t*h.holders[t]['v']for t in h.active)%h.p)
    assert X2==b.mul(h.public['h'],sum(t*t*h.holders[t]['v']for t in h.active)%h.p)
    h.event('original_point_basis_update',original_directions=[h.point_ref(P)for P in [L0,L1,L2]],
        derived_X=h.point_ref(X),derived_X2=h.point_ref(X2),coordinate_equal=True,
        old_target_id=old.target_id,old_target_context_unchanged=True)
    return h.finish({'stage_dimensions':[x['direction_rank']for x in stages],
        'all_subset_tests':[x['targets_checked']for x in stages],'all_targets_protected':True,
        'core_births_at_enrollment':True,'original_points_and_contexts_retained':True,
        'safe_plan_completed_across_enrollment':True}),h.evidence

def old_sum_trace(b,seed):
    h=Harness(b,seed,'retained-sum-new-target');initial_holders(h)
    L=h.complete(h.reserve([1],'old sum'))
    assert h.audit('old sum on four-node dictionary')['status']=='PROTECTED'
    assert not h.enrollment_audit(5,True)
    h.event('diagnostic_counterexample_branch',rule='enroll despite failed common-zero certificate',
            purpose='necessity example; rejected by the proved controller')
    h.enroll(5,'counterexample branch: rejected enrollment executed deliberately',bypass_for_counterexample=True)
    target=h.target([1,2,3,4,5],'new-expanded-target')
    assert [1,2,3,4,5]in h.audit('old sum after enrollment')['recoverable_targets']
    recovery=h.attack(target,L,'old-safe-output-recovers-new-target')
    return h.finish({'old_all_targets_protected':True,'correct_controller_rejects':True,
                     'new_target_recovered':recovery}),h.evidence

def pending_trace(b,seed):
    h=Harness(b,seed,'pending-plan-current-only-failure');initial_holders(h)
    pid=h.reserve([1],'still-completable old sum')
    h.publish(pid,1);h.publish(pid,2)
    assert h.enrollment_audit(5,False)and not h.enrollment_audit(5,True)
    original=[h.point_ref(P)for P in h.plans[pid]['points'].values()]
    h.event('diagnostic_counterexample_branch',rule='current-only audit',
            faulty_rule_accepts=True,plan_aware_rule_rejects=True)
    h.enroll(5,'counterexample branch: current-only test wrongly accepts',bypass_for_counterexample=True)
    target=h.target([1,2,3,4,5],'target-before-old-plan-completion')
    assert h.audit('before pending completion')['status']=='PROTECTED'
    L=h.complete(pid)
    assert original==[h.point_ref(h.plans[pid]['points'][t])for t in [1,2]]
    assert [1,2,3,4,5]in h.audit('after original pending completion')['recoverable_targets']
    recovery=h.attack(target,L,'old-pending-plan-completion-recovers-retained-target')
    return h.finish({'strict_prefix_core_rank':0,'faulty_current_only_accepts':True,
        'correct_pending_aware_rejects':True,'original_partial_points_retained':True,
        'old_plan_used_original_pad_sources':True,'recovery':recovery}),h.evidence

def unpoint(d):return O if d.get('infinity')else Point(int(d['x']),int(d['y']))
def replay_public_evidence(b,evidence,expectations):
    out=[]
    for case in evidence:
        raw=case['public'];pub={'N':raw['N'],'T':[unpoint(x)for x in raw['T']],
            'A':[unpoint(x)for x in raw['A']],'Gamma':unpoint(raw['Gamma']),
            'roots':{int(t):[unpoint(x)for x in pts]for t,pts in raw['roots'].items()}}
        answer,witness=recover(PublicOps(b),pub,case['old_nodes'],case['polynomial_ascending'],
            case['new_node'],unpoint(case['retained_point']),tuple(unpoint(x)for x in case['ciphertext']),b.p)
        expected=expectations[case['target_id']]
        assert digest(b.encode_gt(answer))==expected['expected_gt_sha256']
        assert digest(kdf(b,bytes.fromhex(case['original_context_hex']),answer))==expected['expected_key_sha256']
        assert witness==case['witness']
        out.append({'trace':case['trace'],'target_id':case['target_id'],
                    'public_input_replay':'PASS'})
    return out

def main():
    b=TypeA();checks=backend_selftest(b)
    (HERE/'backend_selftest.json').write_text(json.dumps(checks,indent=2)+'\n')
    traces=[];evidence=[]
    for index in range(2):
        for fn in [safe_trace,old_sum_trace,pending_trace]:
            seed=f'CHARE-coordinate-reference:{index}:{fn.__name__}'
            trace,cases=fn(b,seed);traces.append(trace);evidence.extend(cases)
            print(json.dumps({'trace':trace['trace'],'seed_index':index,'status':'PASS',
                               'events':len(trace['events'])}),flush=True)
    expectations={case['target_id']:{k:case[k]for k in ['expected_gt_sha256','expected_key_sha256']}for case in evidence}
    public_cases=[{k:v for k,v in case.items()if k not in ['expected_gt_sha256','expected_key_sha256','seed']}for case in evidence]
    (HERE/'public_recovery_inputs.json').write_text(json.dumps(public_cases,indent=2)+'\n')
    (HERE/'expected_recovery_hashes.json').write_text(json.dumps(expectations,indent=2)+'\n')
    replays=replay_public_evidence(b,json.loads((HERE/'public_recovery_inputs.json').read_text()),expectations)
    result={'backend':'actual Type-A elliptic-curve coordinates and reduced Tate pairing',
        'p_bits':b.p.bit_length(),'q_bits':b.q.bit_length(),
        'point_representation':'affine x,y only','target_representation':'Fp2 a,b only',
        'recovery_compiler':'unchanged recover function from the preceding delivered increment',
        'selftest_status':checks['status'],'selftest_checks':len(checks['checks']),
        'traces':traces,'public_only_replays':replays,'trace_count':len(traces),
        'actual_recoveries':len(evidence),'measurement_profile':'functional execution; no latency or comparative performance result',
        'status':'PASS'}
    (HERE/'execution_results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'PASS','trace_count':len(traces),'actual_recoveries':len(evidence),
                       'public_only_replays':len(replays)}),flush=True)

if __name__=='__main__':main()
