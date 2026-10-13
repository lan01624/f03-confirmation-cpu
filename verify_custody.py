"""Off-host Owner-operated verifier. Never prints seeds or numerical outcomes."""
import argparse
import base64
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import tarfile
from transport import *

def decrypt(envelope,destination,private_key,expected_provenance,expected_hash):
    require(not os.environ.get('GITHUB_ACTIONS'),'OFF_HOST_ONLY')
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.padding import OAEP,MGF1
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from crypto import fingerprint
    raw=regular(envelope,300_000_000);require(sha(raw)==expected_hash,'ENCRYPTED_ARTIFACT_HASH')
    obj=json.loads(raw);require(set(obj)=={'schema','aad','wrapped_key','nonce','ciphertext'},'ENVELOPE_SCHEMA')
    require(obj['schema']=='R18B4_AES256GCM_RSA3072OAEP_SHA256_V1','ENVELOPE_VERSION')
    b64=lambda n:base64.b64decode(obj[n],validate=True)
    aad=b64('aad');require(json.loads(aad)=={'schema':'R18B4_PUBLIC_ENCRYPTED_CUSTODY_V1','provenance':expected_provenance},'CIPHERTEXT_PROVENANCE')
    key=load_pem_private_key(regular(private_key,20000),password=None)
    require(isinstance(key,RSAPrivateKey) and key.key_size==3072 and fingerprint(key.public_key())==expected_provenance['recipient_sha256'],'OFF_HOST_RECIPIENT')
    secret=key.decrypt(b64('wrapped_key'),OAEP(mgf=MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    plaintext=AESGCM(secret).decrypt(b64('nonce'),b64('ciphertext'),aad)
    # Validate entire archive before writing; no extractall, links, traversal or duplicates.
    entries={};total=0
    with tarfile.open(fileobj=io.BytesIO(plaintext),mode='r:gz') as archive:
        for member in archive:
            name=member.name;p=PurePosixPath(name)
            require(member.isfile() and name==str(p) and not p.is_absolute() and '..' not in p.parts and name not in entries,'ARCHIVE_PATH')
            total+=member.size;require(0<=member.size<=128*1024*1024 and total<=200_000_000,'ARCHIVE_SIZE')
            entries[name]=archive.extractfile(member).read()
    index=json.loads(entries.pop('ARCHIVE_INDEX.json'))
    require(index=={'schema':'R18B4_COMPLETE_CUSTODY_INDEX_V1','files':{n:sha(b) for n,b in entries.items()}},'COMPLETE_ARCHIVE_INDEX')
    require(not destination.exists(),'NO_DECRYPT_OVERWRITE');destination.mkdir(mode=0o700)
    for name,raw in entries.items():
        p=destination/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);os.chmod(p,0o600)

def verify(custody,train_data,expected_provenance,crypto_python,external_trust):
    require(not os.environ.get('GITHUB_ACTIONS'),'OFF_HOST_ONLY');identity=freeze();environment()
    _,measurement,stats=science_modules();permit=read(custody/'permit.json')
    expected={**permit['provenance'],'science':identity,'recipient_sha256':permit['recipient_sha256'],'authorization_sha256':permit['authorization_sha256']}
    require(expected==expected_provenance and permit['science']==identity,'PERMIT_PROVENANCE')
    require(permit['attempt']==1 and permit['retries']==0 and permit['run_seconds']==900 and permit['batch_seconds']==7200,'EXECUTION_CAPS')
    require(read(custody/'claim.json')=={'marker':MARKER,'provenance':permit['provenance']},'MARKER_CUSTODY')
    bundle=read(custody/'authority.json');require(sha(canonical(bundle))==permit['authorization_sha256'],'AUTHORITY_CUSTODY')
    # External pinned public signing keys, never trust the archive's own key claim.
    p=subprocess.run([str(crypto_python),'-B',str(ROOT/'authorize.py'),'audit-authority','--private',str(custody),'--trust',str(external_trust)],
        capture_output=True,timeout=30,check=False)
    require(p.returncode==0,'OWNER_ROLE_AUTHORITY_SIGNATURES')
    seedraw=regular(custody/'private-seeds.json');manifest=json.loads(seedraw);permit_sha=sha(canonical(permit))
    stats.validate_seeds(manifest,permit_sha)
    require(read(custody/'seed-freeze.json')=={'sha256':sha(seedraw),'count':3,'role':'CONFIRMATION'},'SEED_COMMITMENT')
    require(not list(custody.glob('*-FAILED.json')) and not (custody/'BATCH_STOP.json').exists(),'TERMINAL_FAILURE')
    expected_pairs=[b+'-'+a for b in BLOCKS for a in ARMS]
    require({p.name for p in (custody/'fits').iterdir()}==set(expected_pairs),'SIX_ORIGINAL_RECEIPTS')
    require({p.name for p in custody.glob('*-RESULT.json')}=={k+'-RESULT.json' for k in expected_pairs},'SIX_ROWS')
    labels=data_check(train_data);rows=[]
    for arm in ARMS:
        rt=custody/('runtime-'+arm);binding=read(rt/'binding.json')
        require(binding['synthetic'] is False,'RUNTIME_ROLE')
        names={'worker.py':arm+'_worker.py','baseline.py':'baseline.py','boundary.py':'boundary.py','split.json':'split.json',
            'realdata.py':'realdata.py','trusted_entry.py':'confirmation_entry.py','data_binding.json':'data-binding.json'}
        require(set(binding['files'])==set(names) and {p.name for p in rt.iterdir()}==set(names)|{'binding.json'},'RUNTIME_INVENTORY')
        for n,f in names.items():require(regular(rt/n)==(ROOT/'frozen'/f).read_bytes() and sha(regular(rt/n))==binding['files'][n],'RUNTIME_BYTES')
    for block,seed in manifest['blocks'].items():
        for arm in ARMS:
            key=block+'-'+arm;out=custody/'fits'/key;r=read(out/'result.json');row=read(custody/(key+'-RESULT.json'))
            # Seal omits empty scratch. Add no files during off-host verification.
            names={'result.json','checkpoint.pt','private-worker.log'}|{f'validation-{k}-epoch{i}.{ext}' for i in range(1,6) for k,ext in [('logits','npy'),('predictions','json')]}
            require({p.name for p in out.iterdir()}==names and set(row['artifacts'])==names,'FULL_RECEIPT_INVENTORY')
            for name,digest in row['artifacts'].items():require(sha(regular(out/name))==digest,'RECEIPT_HASH')
            payload={k:v for k,v in row.items() if k!='evidence_id'}
            require(row['evidence_id']=='sha256:'+sha(canonical(payload)),'ROW_EVIDENCE_HASH')
            require(row['block']==block and row['arm']==arm and row['role']=='CONFIRMATION' and row['status']=='SUCCEEDED','CELL_IDENTITY')
            require(row['permit_sha256']==permit_sha and row['seed_manifest_sha256']==sha(seedraw),'ROW_BINDINGS')
            require(row['binding_sha256']==sha((custody/('runtime-'+arm)/'binding.json').read_bytes()),'ROW_RUNTIME')
            require(r['status']=='SUCCEEDED' and r['seed']==seed and r['seed_role']=='CONFIRMATION' and r['classification']=='REAL_TRAIN_VALID_CONFIRMATION','ORIGINAL_ROLE')
            require(r['worker_sha256']==identity[('source' if arm=='baseline' else 'candidate')+'_sha256']==row['source_sha256'],'ORIGINAL_WORKER')
            require(r['updates']==3910 and len(r['epochs'])==5 and all(e['epoch']==i and e['updates']==782*i and e['train_count']==50000 and e['validation']['sample_count']==10000 for i,e in enumerate(r['epochs'],1)),'ORIGINAL_FULL_FIDELITY')
            require(r['final_validation']==r['epochs'][-1]['validation'],'ORIGINAL_FINAL_EPOCH')
            m=measurement.verify_outputs(out,r,labels)
            import numpy as np
            for epoch in r['epochs']:
                logits=np.load(out/('validation-logits-epoch'+str(epoch['epoch'])+'.npy'),allow_pickle=False)
                recomputed=measurement.metrics(logits,labels);pred=logits.argmax(1).tolist()
                matrix=[[0 for _ in range(10)] for _ in range(10)]
                for truth,guess in zip(labels,pred):matrix[truth][guess]+=1
                v=epoch['validation']
                require(v['confusion_matrix']==matrix and v['per_class_recall']=={str(k):recomputed['per_class_recall'][k] for k in range(10)} and
                    v['loss']==recomputed['cross_entropy'],'ALL_EPOCH_METRICS_AND_HARMS')
            require(m==row['metrics'] and row['initial_state_sha256']==r['initial_state_sha256'] and row['train_orders']==[e['train_order_sha256'] for e in r['epochs']],'RECOMPUTED_MEASUREMENT')
            require(r['settings']=={'learning_rate':.001,'weight_decay':0.0} and 0<=r['training_seconds']<=900,'ORIGINAL_SETTINGS_AND_CAP')
            if arm=='baseline':require(m['accuracy']>.1 and m['cross_entropy']<math.log(10) and r['epochs'][-1]['train_loss']<r['epochs'][0]['train_loss'],'BASELINE_VERIFIED')
            rows.append(row)
    result=stats.aggregate(rows);require(result==read(custody/'CONFIRMATION_RESULT.json'),'ORIGINAL_PAIRED_T95_AND_HARMS')
    return {'schema':'R18B4_PRIVATE_VERIFICATION_V2','operation':OPERATION,
        'status':'COMPLETE_SIX_FITS_VERIFIED_PENDING_OWNER_QUALITY_REVIEW',
        'provenance':expected_provenance,'scientific_result':result,'complete_six_receipt_verification':True,
        'human_review':'OWNER_OPERATED','independent_human_review':False,
        'quality_limitations':QUALITY_LIMITATIONS,'independent_data':False,'lesson_admission':False,'VALIDATED':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=('decrypt','verify'));p.add_argument('--custody',type=Path,required=True)
    p.add_argument('--provenance',type=Path,required=True);p.add_argument('--envelope',type=Path);p.add_argument('--private-key',type=Path)
    p.add_argument('--encrypted-sha256');p.add_argument('--train-data',type=Path);p.add_argument('--private-report',type=Path)
    p.add_argument('--crypto-python',type=Path);p.add_argument('--external-trust',type=Path);a=p.parse_args()
    try:
        if a.phase=='decrypt':decrypt(a.envelope,a.custody,a.private_key,read(a.provenance),a.encrypted_sha256)
        else:durable(a.private_report,verify(a.custody,a.train_data,read(a.provenance),a.crypto_python,a.external_trust))
        print('OFF_HOST_PHASE_COMPLETE_REVIEW_REQUIRED')
    except BaseException:
        print('OFF_HOST_VERIFICATION_FAILED_NO_RETRY');raise SystemExit(1) from None
