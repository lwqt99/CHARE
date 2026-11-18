#!/usr/bin/env python3
"""Compile represented CHARE witnesses and replay them on a real tiny curve.

The recover() path receives public curve handles, source descriptors and a
normalized coefficient solution. It has no setup trapdoor, holder scalars,
encapsulation scalar, original GT value or expected key as arguments.
Expected outputs belong only to the fixture generator and final comparator.
All encodings and the SHA-256 KDF are this diagnostic's own explicit format.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
from toy_pairing import (Q, R, G, Fq2, add, mul, linear_combination as lc,
                        pairing, encode_point, decode_point, decode_gt,
                        validate_backend)

HERE = Path(__file__).resolve().parent


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def frame(*parts):
    return b''.join(len(p).to_bytes(4, 'big')+p for p in parts)


def key_derive(context: bytes, z: Fq2) -> str:
    return hashlib.sha256(frame(b'CHARE-independent-curve-diagnostic-v1', context, z.encode())).hexdigest()


def point_hex(p):
    return encode_point(p).hex()


def point(h):
    return decode_point(bytes.fromhex(h))


def scalar_solve(matrix, rhs, columns):
    rows = [[v % R for v in row]+[b % R] for row, b in zip(matrix, rhs)]
    at, pivots = 0, []
    for j in range(columns):
        k = next((k for k in range(at, len(rows)) if rows[k][j]), None)
        if k is None:
            continue
        rows[at], rows[k] = rows[k], rows[at]
        scale = pow(rows[at][j], -1, R)
        rows[at] = [v*scale % R for v in rows[at]]
        for i in range(len(rows)):
            if i != at and rows[i][j]:
                scale = rows[i][j]
                rows[i] = [(v-scale*w) % R for v, w in zip(rows[i], rows[at])]
        pivots.append(j)
        at += 1
    if any(not any(row[:columns]) and row[-1] for row in rows):
        return None
    result = [0]*columns
    for i, j in enumerate(pivots):
        result[j] = rows[i][-1]
    assert all(sum(a*b for a, b in zip(row, result)) % R == value % R for row, value in zip(matrix, rhs))
    return result


def polynomial_mul(a, b):
    out = [0]*(len(a)+len(b)-1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] = (out[i+j]+x*y) % R
    return out


def interpolate(nodes, values):
    out = [0]*len(nodes)
    for i, t in enumerate(nodes):
        basis, denominator = [1], 1
        for j, u in enumerate(nodes):
            if j != i:
                basis = polynomial_mul(basis, [-u % R, 1])
                denominator = denominator*(t-u) % R
        scale = values[i]*pow(denominator, -1, R) % R
        for k, c in enumerate(basis):
            out[k] = (out[k]+scale*c) % R
    return out


def polynomial_quotient(q, t, value):
    if len(q) == 1:
        assert q[0] == value % R
        return []
    remainder = q[:]
    remainder[0] = (remainder[0]-value) % R
    quotient = [0]*(len(q)-1)
    for i in range(len(q)-1, 0, -1):
        quotient[i-1] = remainder[i]
        remainder[i-1] = (remainder[i-1]+t*remainder[i]) % R
        remainder[i] = 0
    assert not any(remainder)
    return quotient


def gamma(nodes):
    out = []
    for i, t in enumerate(nodes):
        denominator = 1
        for j, u in enumerate(nodes):
            if j != i:
                denominator = denominator*(t-u) % R
        out.append(pow(denominator, -1, R))
    return out


def represented_solution(target, releases):
    """Jointly solve for x and all point coefficients, not one formal x first."""
    validate_dimensions(target, releases)
    n, m = len(target['nodes']), len(releases)
    d = len(target['F_columns'][0])
    rows, rhs = [], []
    for i, eta in enumerate(target['eta']):
        row = [0]*(n+m)
        row[i] = eta
        rows.append(row); rhs.append(0)
    for a in range(d):
        rows.append([col[a] for col in target['F_columns']]+[-z['descriptor'][a] for z in releases])
        rhs.append(0)
    rows.append(gamma(target['nodes'])+[0]*m);rhs.append(-1)
    solved = scalar_solve(rows, rhs, n+m)
    return None if solved is None else {'x':solved[:n], 'point_coefficients':solved[n:]}


def validate_dimensions(target, releases=None):
    n = len(target['nodes'])
    if not n or len(set(target['nodes'])) != n:
        raise ValueError('Target nodes must be nonempty and distinct')
    if any(len(target[k]) != n for k in ['X','projections','F_columns','eta']):
        raise ValueError('Target dimensions differ')
    d = len(target['F_columns'][0])
    if not d or any(len(c) != d for c in target['F_columns']):
        raise ValueError('Target source-column widths differ')
    if releases is not None and any(len(v['descriptor']) != d for v in releases):
        raise ValueError('Represented descriptor widths differ')


def validate_target(pp, target):
    validate_dimensions(target)
    setup_bytes = canonical_json({k:v for k,v in pp.items() if k != 'setup_id'})
    if hashlib.sha256(setup_bytes).hexdigest() != pp['setup_id']:
        raise ValueError('Public setup digest mismatch')
    if target['setup_id'] != pp['setup_id']:
        raise ValueError('Original setup binding mismatch')
    if any(t < 1 or t > pp['N'] for t in target['nodes']):
        raise ValueError('Target node is outside setup capacity')
    expected_context = canonical_json(target['context_object'])
    if target['context_hex'] != expected_context.hex():
        raise ValueError('Original context bytes changed')
    bound = target['context_object']
    if bound['setup_id'] != pp['setup_id']:
        raise ValueError('Original context setup binding mismatch')
    for name in ['C0', 'C1', 'nodes', 'X', 'projections']:
        if bound[name] != target[name]:
            raise ValueError('Original target binding changed: '+name)
    g = point(pp['g'])
    for t, first, projections in zip(target['nodes'], target['X'], target['projections']):
        if len(projections) != pp['N']-1:
            raise ValueError('Incomplete projection ladder')
        for k, projection in enumerate(projections):
            base = lc([(1, point(pp['T'][k+1])), (-t, point(pp['T'][k]))])
            if pairing(point(first), base) != pairing(g, point(projection)):
                raise ValueError('Projection check failed')


def recover(pp, target, releases, solution):
    validate_target(pp, target)
    validate_dimensions(target, releases)
    x, weights = solution['x'], solution['point_coefficients']
    if len(x) != len(target['nodes']) or len(weights) != len(releases):
        raise ValueError('Witness dimensions differ')
    if any(e*v % R for e, v in zip(target['eta'], x)) or sum(a*b for a,b in zip(gamma(target['nodes']),x)) % R != R-1:
        raise ValueError('Witness residual/normalization check failed')
    d = len(target['F_columns'][0])
    for a in range(d):
        left = sum(x[j]*target['F_columns'][j][a] for j in range(len(x))) % R
        right = sum(weights[j]*releases[j]['descriptor'][a] for j in range(len(weights))) % R
        if left != right:
            raise ValueError('Actual represented source coefficients do not match')
    for item, coefficient in zip(releases, weights):
        if coefficient and not item.get('observer_available', False):
            raise ValueError('A required source recipe is not observer available')
    q = interpolate(target['nodes'], x)
    if q[-1] != R-1:
        raise ValueError('Interpolant lacks leading coefficient -1')
    n, N = len(x), pp['N']
    qh = lc((a, point(pp['T'][k])) for k,a in enumerate(q))
    terms = [(1,point(pp['Gamma']))]
    terms += [(-q[k], point(pp['A'][N-n+k])) for k in range(n-1)]
    for i,t in enumerate(target['nodes']):
        quotient = polynomial_quotient(q,t,x[i])
        terms += [(-c,point(target['projections'][i][k])) for k,c in enumerate(quotient)]
    L = lc((a,point(item['point'])) for a,item in zip(weights,releases))
    terms.append((-1,L))
    rh = lc(terms)
    recovered = pairing(point(target['C0']),rh)*pairing(point(target['C1']),qh)
    context = bytes.fromhex(target['context_hex'])
    return {'status':'TOY_CURVE_REPLAY_VERIFIED_CANDIDATE', 'q':q, 'x':x,
            'point_coefficients':weights, 'L':point_hex(L), 'Q_h':point_hex(qh),
            'R_h':point_hex(rh), 'GT_hex':recovered.encode().hex(),
            'key_sha256':key_derive(context,recovered),
            'context_sha256':hashlib.sha256(context).hexdigest()}


def setup(N):
    # Fixture generation only. No scalar in this tuple is passed to recover().
    a,beta,theta,alpha,tau = 7,11,19,9,20
    h = mul(theta,G)
    pp = {'N':N,'g':point_hex(G),'h':point_hex(h),
          'Y':[point_hex(mul(a*pow(tau,k,R)%R,G)) for k in range(N)],
          'W':{str(t):point_hex(mul(beta*pow(tau-t,-1,R)%R,G)) for t in range(1,N+1)},
          'T':[point_hex(mul(pow(tau,k,R),h)) for k in range(N)],
          'A':[point_hex(mul(a*pow(tau,k,R)%R,h)) for k in range(N-1)],
          'B':[point_hex(mul(beta*pow(tau,k,R)%R,h)) for k in range(N-1)],
          'Gamma':point_hex(mul((alpha+a*pow(tau,N-1,R))%R,h)),
          'Z':(pairing(G,h)**alpha).encode().hex()}
    pp['setup_id']=hashlib.sha256(canonical_json(pp)).hexdigest()
    return pp, {'a':a,'beta':beta,'theta':theta,'alpha':alpha,'tau':tau}


def make_fixture(name,N,nodes,core_values,release_rows,*,masked=False):
    pp,secrets=setup(N);h=point(pp['h']);tau=secrets['tau'];s=8
    d=N+(len(nodes) if masked else 0);masks=[31,47,61,73][:len(nodes)];weight=3
    X=[];projections=[];F=[]
    for j,t in enumerate(nodes):
        root=mul(core_values[t-1],G)
        root_projections=[mul(core_values[t-1],lc([(1,point(pp['T'][k+1])),(-t,point(pp['T'][k]))])) for k in range(N-1)]
        f=[0]*d;f[t-1]=1
        if masked:
            E=lc([(masks[j],G),(-1,point(pp['W'][str(t)]))])
            decision=[lc([(masks[j],lc([(1,point(pp['T'][k+1])),(-t,point(pp['T'][k]))])),(-1,point(pp['B'][k]))]) for k in range(N-1)]
            first=lc([(1,root),(weight,point(pp['W'][str(t)])),(weight,E)])
            ladder=[lc([(1,root_projections[k]),(weight,point(pp['B'][k])),(weight,decision[k])]) for k in range(N-1)]
            f[N+j]=weight
        else:
            first,ladder=root,root_projections
        X.append(point_hex(first));projections.append([point_hex(v) for v in ladder]);F.append(f)
    aggregate=lc([(1,point(pp['Y'][N-len(nodes)]))]+[(1,point(x)) for x in X])
    C0=point_hex(mul(s,G));C1=point_hex(mul(s,aggregate))
    binding={'instance':name,'setup_id':pp['setup_id'],'snapshot':'original-snapshot',
             'record_ids':['root-'+str(t)+'-original' for t in nodes],
             'policy':['qualification-A'] if masked else [],'signs':[1] if masked else [],
             'weights':[weight] if masked else [],'nodes':nodes,'X':X,'projections':projections,'C0':C0,'C1':C1}
    target={'setup_id':pp['setup_id'],'nodes':nodes,'X':X,'projections':projections,
            'F_columns':F,'eta':[0]*len(nodes),'C0':C0,'C1':C1,
            'context_object':binding,'context_hex':canonical_json(binding).hex()}
    releases=[]
    for i,row in enumerate(release_rows):
        value=sum(a*b for a,b in zip(row,core_values))%R
        releases.append({'source_id':f'visible-release-{i}','descriptor':row+[0]*(d-N),
                         'point':point_hex(mul(value,h)),'observer_available':True,
                         'recipe':{'kind':'observed_core_sum','core_source_ids':[f'core-{t}' for t in range(1,N+1)]}})
    if masked:
        for j,value in enumerate(masks):
            row=[0]*d;row[N+j]=1
            releases.append({'source_id':f'opened-mask-{j}','descriptor':row,
                             'point':point_hex(mul(value,h)),'observer_available':True,
                             'recipe':{'kind':'public_scalar_times_h','scalar':value,'scalar_origin':'explicit-mask-grant'}})
    z=decode_gt(bytes.fromhex(pp['Z']))**s
    expected={'GT_hex':z.encode().hex(),'key_sha256':key_derive(bytes.fromhex(target['context_hex']),z)}
    return {'name':name,'backend':'E/F_523 order-131 reduced Tate pairing',
            'public_setup':pp,'target':target,'represented_points':releases,
            'expected_encapsulator_output':expected,
            'scope':'Independent real tiny-curve fixture. Not the original PBC artifact, parameters, encoding, authentication or native performance.'}


def main():
    backend=validate_backend();results=[];negative=[]
    fixtures=[
        make_fixture('old_pair_after_third_moment',4,[1,2],[4,13,22,51],[[1,1,1,1],[1,2,3,4],[1,4,9,16]]),
        make_fixture('overlapping_pair_sums',3,[1,2],[4,13,22],[[1,0,1],[0,1,1]]),
        make_fixture('qualified_mask_correction',4,[1,2],[4,13,22,51],[[1,1,1,1],[1,2,3,4],[1,4,9,16]],masked=True),
        make_fixture('singleton_empty_sum_boundary',2,[1],[4,13],[[1,0]]),
        make_fixture('independent_represented_witness_search',2,[1,2],[4,13],[[0,1]]),
    ]
    fixture_dir=HERE/'fixtures';fixture_dir.mkdir(exist_ok=True)
    for fixture in fixtures:
        pp,target,releases=fixture['public_setup'],fixture['target'],fixture['represented_points']
        solution=represented_solution(target,releases);assert solution is not None
        replay=recover(pp,target,releases,solution)
        assert replay['GT_hex']==fixture['expected_encapsulator_output']['GT_hex']
        assert replay['key_sha256']==fixture['expected_encapsulator_output']['key_sha256']
        replay['status']='TOY_CURVE_REPLAY_VERIFIED'
        fixture['represented_solution']=solution;fixture['replay']=replay
        (fixture_dir/(fixture['name']+'.json')).write_text(json.dumps(fixture,indent=2)+'\n')
        results.append({'name':fixture['name'],**replay})
        # Same recovered group element with a different context must not match.
        z=decode_gt(bytes.fromhex(replay['GT_hex']))
        assert key_derive(bytes.fromhex(target['context_hex'])+b'changed',z)!=replay['key_sha256']
        negative.append({'case':fixture['name']+'_wrong_context','result':'key mismatch'})
    old=fixtures[0]
    assert represented_solution(old['target'],old['represented_points'][:2]) is None
    negative.append({'case':'old_pair_only_two_moments','result':'no represented solution'})
    current=make_fixture('current_four_after_three_moments',4,[1,2,3,4],[4,13,22,51],[[1,1,1,1],[1,2,3,4],[1,4,9,16]])
    assert represented_solution(current['target'],current['represented_points']) is None
    negative.append({'case':'current_four_same_three_moments','result':'no represented solution in supplied span'})
    masked=fixtures[2]
    assert represented_solution(masked['target'],masked['represented_points'][:3]) is None
    negative.append({'case':'masked_target_without_mask_corrections','result':'no represented solution'})
    unavailable=copy.deepcopy(masked['represented_points']);unavailable[3]['observer_available']=False;unavailable[4]['observer_available']=False
    def rejected(case,fn):
        try:
            fn()
        except ValueError as e:
            negative.append({'case':case,'result':'rejected','reason':str(e)})
        else:
            raise AssertionError('Expected rejection: '+case)
    rejected('private_auditor_mask_not_public_recipe',lambda:recover(masked['public_setup'],masked['target'],unavailable,masked['represented_solution']))
    changed=copy.deepcopy(old['target']);changed['C1']=point_hex(add(point(changed['C1']),G))
    rejected('changed_original_ciphertext',lambda:recover(old['public_setup'],changed,old['represented_points'],old['represented_solution']))
    changed=copy.deepcopy(old['target']);changed['projections'][0][0]=point_hex(add(point(changed['projections'][0][0]),G))
    # Rebind the changed public record so this test reaches the projection check.
    changed['context_object']['projections']=copy.deepcopy(changed['projections']);changed['context_hex']=canonical_json(changed['context_object']).hex()
    rejected('invalid_projection_coordinate',lambda:recover(old['public_setup'],changed,old['represented_points'],old['represented_solution']))
    wrong=copy.deepcopy(old['represented_solution']);wrong['x'][0]=(wrong['x'][0]+1)%R
    rejected('wrong_normalized_witness',lambda:recover(old['public_setup'],old['target'],old['represented_points'],wrong))
    changed_points=copy.deepcopy(old['represented_points'])
    changed_points[2]['point']=point_hex(add(point(changed_points[2]['point']),point(old['public_setup']['h'])))
    false_descriptor_candidate=recover(old['public_setup'],old['target'],changed_points,old['represented_solution'])
    assert false_descriptor_candidate['GT_hex']!=old['expected_encapsulator_output']['GT_hex']
    assert false_descriptor_candidate['key_sha256']!=old['expected_encapsulator_output']['key_sha256']
    negative.append({'case':'incorrect_group_handle_with_unchanged_descriptor','result':'GT and key mismatch; candidate is not verified recovery'})
    alternate=fixtures[-1]
    assert alternate['represented_solution']['x']==[0,R-1]
    assert gamma([1,2])[0]*1 % R == R-1  # x=(1,0) is a formal alternative.
    assert alternate['represented_solution']['x']!=[1,0]
    negative.append({'case':'first_formal_vector_unrepresented_but_another_exists','result':'joint represented-space search finds x=(0,-1)'})
    truncated=copy.deepcopy(old['target']);truncated['X'].pop()
    rejected('truncated_target_columns',lambda:recover(old['public_setup'],truncated,old['represented_points'],old['represented_solution']))
    narrow=copy.deepcopy(old['represented_points']);narrow[0]['descriptor'].pop()
    rejected('inconsistent_descriptor_width',lambda:recover(old['public_setup'],old['target'],narrow,old['represented_solution']))
    bad_setup=copy.deepcopy(old['public_setup']);bad_setup['A'][0]=point_hex(add(point(bad_setup['A'][0]),G))
    rejected('changed_setup_with_old_digest',lambda:recover(bad_setup,old['target'],old['represented_points'],old['represented_solution']))
    bad_context=copy.deepcopy(old['target']);bad_context['context_object']['setup_id']='different-setup';bad_context['context_hex']=canonical_json(bad_context['context_object']).hex()
    rejected('context_setup_mismatch',lambda:recover(old['public_setup'],bad_context,old['represented_points'],old['represented_solution']))
    summary={'backend_checks':backend,'successful_replays':results,'negative_checks':negative,
             'successful_replay_count':len(results),'negative_check_count':len(negative),
             'recover_function_uses_secret_exponents':False,'native_paper_artifact_replayed':False,
             'new_native_performance_claimed':False,
             'scope':'Actual tiny-curve coordinate/pairing/serialization and original-fixture-context KDF checks. This is a new independent diagnostic, not native-paper reproduction.'}
    (HERE/'curve_replay_results.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ['successful_replays','negative_checks']},indent=2))


if __name__=='__main__':
    main()
