import math, statistics
BLOCKS=('block-01','block-02','block-03')
EXCLUDED=frozenset([4901,4902,4903,5201,5202,5203,6101,6102,6103])
def require(ok,message):
    if not ok:raise ValueError(message)

def validate_seeds(manifest,permit_sha):
    require(set(manifest)=={'schema','seed_role','permit_sha256','blocks'},'SEED_SCHEMA')
    require(manifest['schema']=='R18B4_PRIVATE_SEEDS_V1' and manifest['seed_role']=='CONFIRMATION' and manifest['permit_sha256']==permit_sha,'SEED_BINDING')
    require(list(manifest['blocks'])==list(BLOCKS),'THREE_FIXED_BLOCKS')
    values=list(manifest['blocks'].values())
    require(len(set(values))==3 and all(type(x) is int and 1<=x<2**31 and x not in EXCLUDED for x in values),'FRESH_DISJOINT_SEEDS')
    return values


def aggregate(rows):
    # No seed values enter this evaluator result; original receipts remain private.
    require(len(rows)==6 and [(r['block'],r['arm']) for r in rows]==[(b,a) for b in BLOCKS for a in ('baseline','candidate')],'INCOMPLETE_CONFIRMATION')
    require(all(r['status']=='SUCCEEDED' and r['role']=='CONFIRMATION' for r in rows),'INVALID_CONFIRMATION_EXECUTION')
    require(len({r['evidence_id'] for r in rows})==6,'DUPLICATE_EVIDENCE')
    for a,b in zip(rows[::2],rows[1::2]):
        require(a['initial_state_sha256']==b['initial_state_sha256'] and a['train_orders']==b['train_orders'],'PAIR_SUPPORT')
    contrasts={}
    for k in ('primary_recall_5_6','accuracy','macro_recall','cross_entropy'):
        d=[b['metrics'][k]-a['metrics'][k] for a,b in zip(rows[::2],rows[1::2])]
        require(all(math.isfinite(v) for v in d),'NONFINITE_METRIC')
        mean=statistics.mean(d);sd=statistics.stdev(d);width=4.302652729911275*sd/math.sqrt(3)
        contrasts[k]={'differences':d,'mean':mean,'sample_sd':sd,'conditional_t95_df2':[mean-width,mean+width]}
    p=contrasts['primary_recall_5_6'];low,high=p['conditional_t95_df2']
    # Zero empirical variance cannot establish seed-distribution certainty at n=3.
    status='INCONCLUSIVE' if p['sample_sd']==0 else ('DIRECTION_SUPPORTED_PENDING_PI' if low>0 else 'DIRECTION_REFUTED_PENDING_PI' if high<=0 else 'INCONCLUSIVE')
    return {'schema':'R18B4_PRIVATE_CONFIRMATION_RESULT_V1','status':status,'valid_blocks':3,'contrasts':contrasts,
        'class_differences':[[b['metrics']['per_class_recall'][i]-a['metrics']['per_class_recall'][i] for i in range(10)] for a,b in zip(rows[::2],rows[1::2])],
        'adequacy':'N3_NORMAL_SEED_APPROXIMATION_NOT_EMPIRICALLY_ESTABLISHED_REQUIRES_PI_REVIEW',
        'common_support':'THREE_COMPLETE_PAIRED_BLOCKS_SAME_FIXED_VALID','independent_data':False,
        'individual_factor_attribution':False,'VALIDATED':False,'lesson_admission':False}
