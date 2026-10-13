"""One bounded integration: real sandbox micro-workers, production batch/finalization."""
import os
from pathlib import Path
import sys
import tempfile
import execute
from transport import *

def verify_replay(original,replay):
    for key in ('initial_state_sha256','state_sha256'):
        require(original[key]==replay[key],'NUMERICAL_REPLAY_'+key.upper())
    for key in ('train_order_sha256','train_loss','train_online_accuracy'):
        require(original['epochs'][0][key]==replay['epochs'][0][key],'NUMERICAL_REPLAY_'+key.upper())
    # Wall-clock evaluation duration is not a numerical scientific output.
    first={k:v for k,v in original['final_validation'].items() if k!='evaluation_seconds'}
    second={k:v for k,v in replay['final_validation'].items() if k!='evaluation_seconds'}
    require(first==second,'NUMERICAL_REPLAY_VALIDATION')

def qualify(destination):
    identity=freeze();env=environment();patch_parity();split_ids()
    with tempfile.TemporaryDirectory(prefix='recovery-synthetic-',dir=os.environ.get('RUNNER_TEMP')) as tmp:
        p=Path(tmp);custody=p/'custody';custody.mkdir();(p/'empty-data').mkdir()
        manifest={'schema':'SYNTHETIC_ENGINEERING_ONLY','blocks':dict(zip(BLOCKS,[7101,7102,7103]))}
        durable(custody/'private-seeds.json',manifest)
        runtimes={a:(p/('runtime-'+a),None) for a in ARMS}
        for a,(rt,_) in runtimes.items():runtimes[a]=(rt,materialize(rt,a,True))
        rows=execute.batch(p,custody,manifest,'SYNTHETIC_NO_AUTHORITY',runtimes,list(range(10))*2,synthetic=True)
        require(len(rows)==6 and all(r['role']=='SYNTHETIC_ENGINEERING' and r['status']=='SUCCEEDED' for r in rows),'SYNTHETIC_BATCH')
        require(not list(custody.glob('*-FAILED.json')),'CONTRADICTORY_RECEIPTS')
        require(not list((custody/'fits').glob('*/scratch')),'SCRATCH_EXCLUDED')
        for row in rows:
            out=custody/'fits'/(row['block']+'-'+row['arm']);r=read(out/'result.json')
            require(all(r['isolation'].values()) and r['official_test_reads']==0,'REAL_BOUNDARY_REQUIRED')
            require(row['artifacts']=={f.name:sha(regular(f)) for f in out.iterdir()},'FINAL_RECEIPT_FILES')
        # One deterministic replay of the first synthetic pair; no production draw.
        for arm,first in zip(ARMS,rows[:2]):
            rt,binding=runtimes[arm];out=p/('replay-'+arm)
            replay=launch(rt,p/'empty-data',out,7101,custody/'private-seeds.json',binding,True)
            original=read(custody/'fits'/('block-01-'+arm)/'result.json')
            verify_replay(original,replay)
    durable(destination,{'schema':'R18B4_RECOVERY_SYNTHETIC_INTEGRATION_V1','status':'PASS',
        'operation':OPERATION,'commit':os.environ.get('GITHUB_SHA'),'manifest_sha256':sha((ROOT/'MANIFEST.json').read_bytes()),
        'science':identity,'environment':env,'production_batch_finalization':True,'successful_receipts':6,
        'synthetic_micro_runs':8,'numerical_replay':True,'paired_initialization_and_order':True,
        'landlock_seccomp_denials':True,'scratch_absent_from_custody':True,'confirmation_seed_draws':0,
        'full_fidelity_fits':0,'official_test_access':0,'scientific_confirmation':False})

if __name__=='__main__':qualify(Path(sys.argv[1]))
