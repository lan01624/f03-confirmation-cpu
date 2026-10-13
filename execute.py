"""Prospective six-fit custody orchestration. Separately authorized production only."""
import argparse
import math
import os
from pathlib import Path
import secrets
import time
from transport import *

def preflight(private):
    freeze();env=environment();split_ids();patch_parity()
    custody=private/'custody';require(custody.is_dir(),'AUTHORITY_REQUIRED')
    durable(custody/'runtime.json',env)
    download_train(private/'train-data')
    # Same trusted entry and actual boundary, only synthetic data; no confirmation draw.
    rt=private/'preflight-runtime';binding=materialize(rt,'baseline',True)
    out=private/'preflight-synthetic';empty=private/'empty-data';empty.mkdir()
    launch(rt,empty,out,7101,custody/'permit.json',binding,True)
    durable(custody/'preflight.json',{'status':'SYNTHETIC_BOUNDARY_AND_RUNTIME_QUALIFIED','confirmation_draws':0})

def run(private):
    identity=freeze();context=hosted_context('confirmation.yml');environment()
    require(read(ROOT/'activation.json')['real_execution_authorized'] is True,'PRODUCTION_DISABLED')
    for key in ('GH_TOKEN','GITHUB_TOKEN','DEEPSEEK_API_KEY','R18B4_SIGNED_AUTHORIZATION','R18B4_REVIEWER_APPROVAL_SHA256'):
        require(not os.environ.get(key),'CREDENTIAL_IN_FIT_HOST')
    custody=private/'custody';permit=read(custody/'permit.json')
    require(permit['provenance']==context and permit['science']==identity,'PERMIT_IDENTITY')
    require(read(custody/'claim.json')=={'marker':MARKER,'provenance':context},'PUBLIC_MARKER_REQUIRED')
    require(read(custody/'preflight.json')['status']=='SYNTHETIC_BOUNDARY_AND_RUNTIME_QUALIFIED','PREFLIGHT_REQUIRED')
    require(read(custody/'authority.json')['authorization']['expires_unix']>time.time(),'AUTHORIZATION_EXPIRED')
    durable(custody/'execution-started.json',{'status':'STARTED_NO_RESTART','provenance':context,'unix':time.time()})
    permit_sha=sha(canonical(permit))
    durable(custody/'seed-generation-started.json',{'permit_sha256':permit_sha,'status':'STARTED_NO_RESTART'})
    values=[]
    while len(values)<3:
        n=secrets.randbelow(2**31-1)+1
        if n not in EXCLUDED and n not in values:values.append(n)
    manifest={'schema':'R18B4_PRIVATE_SEEDS_V1','seed_role':'CONFIRMATION','permit_sha256':permit_sha,'blocks':dict(zip(BLOCKS,values))}
    _,measurement,stats=science_modules();stats.validate_seeds(manifest,permit_sha)
    durable(custody/'private-seeds.json',manifest);os.chmod(custody/'private-seeds.json',0o600)
    durable(custody/'seed-freeze.json',{'sha256':sha((custody/'private-seeds.json').read_bytes()),'count':3,'role':'CONFIRMATION'})
    labels=data_check(private/'train-data');runtimes={}
    for arm in ARMS:
        rt=private/('runtime-'+arm);runtimes[arm]=(rt,materialize(rt,arm,False))
        # Preserve all exact executable bytes and bindings inside encrypted custody.
        dest=custody/('runtime-'+arm);dest.mkdir()
        for f in rt.iterdir():(dest/f.name).write_bytes(regular(f))
    fits=custody/'fits';fits.mkdir();rows=[];start=time.monotonic()
    for block,seed in manifest['blocks'].items():
        for arm in ARMS:
            key=block+'-'+arm
            durable(custody/(key+'-STARTED.json'),{'block':block,'arm':arm,'attempt':1,'status':'STARTED'})
            try:
                require(time.monotonic()-start+900<=7200,'BATCH_CAP_STOP_NO_RETRY')
                rt,binding=runtimes[arm];out=fits/key
                r=launch(rt,private/'train-data',out,seed,custody/'private-seeds.json',binding)
                require(r['seed']==seed and r['seed_role']=='CONFIRMATION' and r['classification']=='REAL_TRAIN_VALID_CONFIRMATION' and
                    r['updates']==3910 and len(r['epochs'])==5 and all(e['train_count']==50000 for e in r['epochs']),'FULL_FIDELITY')
                m=measurement.verify_outputs(out,r,labels)
                require(r['final_validation']==r['epochs'][-1]['validation'],'FINAL_EPOCH_ONLY')
                if arm=='baseline':require(m['cross_entropy']<math.log(10) and m['accuracy']>.1 and r['epochs'][-1]['train_loss']<r['epochs'][0]['train_loss'],'BASELINE_FAILED')
                row={'block':block,'arm':arm,'role':'CONFIRMATION','status':'SUCCEEDED','metrics':m,
                    'initial_state_sha256':r['initial_state_sha256'],'train_orders':[e['train_order_sha256'] for e in r['epochs']],
                    'source_sha256':r['worker_sha256'],'binding_sha256':binding,'permit_sha256':permit_sha,
                    'seed_manifest_sha256':sha((custody/'private-seeds.json').read_bytes())}
                if arm=='candidate':require(row['initial_state_sha256']==rows[-1]['initial_state_sha256'] and row['train_orders']==rows[-1]['train_orders'],'PAIR_SUPPORT')
                row['artifacts']={f.name:sha(regular(f)) for f in out.iterdir() if f.name!='scratch'}
                row['evidence_id']='sha256:'+sha(canonical(row))
                durable(custody/(key+'-RESULT.json'),row);rows.append(row)
                # Scratch never leaves evaluator; require it empty before removing.
                (out/'scratch').rmdir()
            except BaseException:
                durable(custody/(key+'-FAILED.json'),{'status':'INVALID_EXECUTION','metrics':None,'retry':False})
                raise
    durable(custody/'CONFIRMATION_RESULT.json',stats.aggregate(rows))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=('preflight','execute'));p.add_argument('--private',type=Path,required=True);a=p.parse_args()
    try:
        (preflight if a.phase=='preflight' else run)(a.private.resolve());print('PHASE_FINISHED_NO_PUBLIC_OUTCOMES')
    except BaseException:
        print('TERMINAL_STOP_NO_RETRY');raise SystemExit(1) from None
