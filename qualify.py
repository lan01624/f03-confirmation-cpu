"""Synthetic-only public Linux qualification; never draws confirmation seeds."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from transport import *

def qualify(destination):
    identity=freeze();context=hosted_context('synthetic.yml');env=environment();patch_parity();split_ids()
    with tempfile.TemporaryDirectory(prefix='f03-synthetic-',dir=os.environ['RUNNER_TEMP']) as tmp:
        p=Path(tmp);data=p/'empty-data';data.mkdir()
        canary=p/'private-file';canary.write_text('SYNTHETIC_DENIED_PRIVATE_CAPABILITY')
        test_canary=p/'official-test-canary';test_canary.write_text('SYNTHETIC_ONLY_NO_DATASET')
        rows=[]
        for arm in ARMS:
            rt=p/('runtime-'+arm);binding=materialize(rt,arm,True)
            a=launch(rt,data,p/(arm+'-first'),7101,canary,binding,True)
            b=launch(rt,data,p/(arm+'-repeat'),7101,test_canary,binding,True)
            require(a['classification']==b['classification']=='SYNTHETIC_ENGINEERING','SYNTHETIC_ROLE')
            require(a['updates']==b['updates']==1 and a['epochs'][0]['train_count']==20,'MICRO_ONLY')
            require(a['initial_state_sha256']==b['initial_state_sha256'] and a['state_sha256']==b['state_sha256'],'NUMERICAL_REPLAY')
            for k in ('train_order_sha256','train_loss','train_online_accuracy'):
                require(a['epochs'][0][k]==b['epochs'][0][k],'NUMERICAL_REPLAY')
            for k in ('logits_sha256','prediction_sha256','ground_truth_sha256','accuracy','loss','confusion_matrix','per_class_recall'):
                require(a['final_validation'][k]==b['final_validation'][k],'NUMERICAL_REPLAY')
            _,m,_=science_modules()
            for suffix,r in [('first',a),('repeat',b)]:m.verify_outputs(p/(arm+'-'+suffix),r,list(range(10))*2,epochs=1)
            require(all(a['isolation'].values()) and all(b['isolation'].values()),'SANDBOX_DENIAL')
            rows.append(a)
        require(rows[0]['initial_state_sha256']==rows[1]['initial_state_sha256'],'PAIRED_INITIALIZATION')
        require(rows[0]['epochs'][0]['train_order_sha256']==rows[1]['epochs'][0]['train_order_sha256'],'PAIRED_ORDER')
    durable(destination,{'schema':'R18B4_PUBLIC_SYNTHETIC_V1','status':'PUBLIC_RUNNER_SYNTHETIC_QUALIFIED',
        'provenance':context,'environment':env,'science':identity,'checks':{'patch_apply_reverse':True,'numerical_replay':True,
        'paired_init_order':True,'private_denied':True,'test_canary_denied':True,'network_denied':True,'process_denied':True},
        'full_fidelity_fits':0,'confirmation_seed_draws':0,'official_test_access':0,'independent_confirmation':False})

if __name__=='__main__':
    try:qualify(Path(sys.argv[1]));print('PUBLIC_RUNNER_SYNTHETIC_QUALIFIED')
    except BaseException:
        print('SYNTHETIC_QUALIFICATION_FAILED_NO_RUNTIME_FALLBACK');raise SystemExit(1) from None
