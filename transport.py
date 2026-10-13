"""Owner-operated transport V2. No Agent, private client, or training rewrite."""
from __future__ import annotations
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import site
import stat
import subprocess
import sys
import tempfile
import types
import urllib.request

ROOT=Path(__file__).resolve().parent
REPOSITORY='lan01624/f03-confirmation-cpu'
REPOSITORY_ID=1417070173
OPERATION='R18B4_F03_RECOVERY_CONFIRMATION_V1'
OWNER_LOGIN='lan01624'
OWNER_ID=260238692
QUALITY_LIMITATIONS={'seed_blocks':3,'paired_t_degrees_of_freedom':2,
    'conditional_normal_approximation':True,'same_validation_data':True,
    'independent_data':False,'independent_human_review':False,
    'all_class_harms_reviewed':True,'negative_results_retained':True}
MARKER='refs/tags/r18b4-public-recovery-confirmation-v1-consumed'
WORKFLOW='recovery.yml'
BLOCKS=('block-01','block-02','block-03')
ARMS=('baseline','candidate')
EXCLUDED=frozenset((4901,4902,4903,5201,5202,5203,6101,6102,6103))

def require(ok,code):
    if not ok:raise ValueError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def durable(path,value):
    with Path(path).open('xb') as f:
        f.write(canonical(value)+b'\n');f.flush();os.fsync(f.fileno())
    fd=os.open(Path(path).parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def regular(path,limit=128*1024*1024):
    p=Path(path);s=p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,'REGULAR_FILE_REQUIRED')
    return p.read_bytes()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m

def science_modules():
    for name in ('aera_ml','aera_ml.evaluation'):
        pkg=types.ModuleType(name);pkg.__path__=[];sys.modules[name]=pkg
    decoder=load('aera_ml.evaluation.realdata',ROOT/'frozen/realdata.py')
    measurement=load('f03_measurement',ROOT/'frozen/measurement.py')
    aggregate=load('f03_statistics',ROOT/'frozen/statistics.py')
    return decoder,measurement,aggregate

def freeze():
    manifest=read(ROOT/'MANIFEST.json')
    require(manifest['schema']=='R18B4_PUBLIC_FILES_V1','MANIFEST_SCHEMA')
    actual=set()
    for p in ROOT.rglob('*'):
        rel=p.relative_to(ROOT)
        if rel.parts[0]=='.git':continue
        require(not p.is_symlink(),'NO_SOURCE_SYMLINKS')
        if p.is_file():actual.add(str(rel))
    require(actual==set(manifest['files'])|{'MANIFEST.json'},'STRICT_SOURCE_ALLOWLIST')
    for p,d in manifest['files'].items():
        require(not Path(p).is_absolute() and '..' not in Path(p).parts,'MANIFEST_PATH')
        require(sha(regular(ROOT/p))==d,'PUBLIC_BYTES_CHANGED')
    identity=read(ROOT/'frozen/identity.json')
    for key,name in [('source','baseline_worker.py'),('candidate','candidate_worker.py'),('patch','ORIGINAL.patch'),
                     ('original_entry','original_entry.py'),('confirmation_entry','confirmation_entry.py')]:
        require(sha((ROOT/'frozen'/name).read_bytes())==identity[key+'_sha256'],'SCIENTIFIC_IDENTITY')
    for key,name in [('protocol','CONFIRMATION_PROTOCOL.json'),('spec','CONFIRMATION_SPEC.json'),('runtime_lock','runtime-lock.txt')]:
        require(sha((ROOT/'frozen'/name).read_bytes())==identity[key+'_sha256'],'SCIENTIFIC_COMMITMENT')
    return identity

def patch_parity():
    with tempfile.TemporaryDirectory(prefix='f03-patch-') as d:
        p=Path(d);source=(ROOT/'frozen/baseline_worker.py').read_bytes()
        (p/'worker.py').write_bytes(source)
        for args in [('apply','--check'),('apply',)]:
            subprocess.run(['git',*args,str(ROOT/'frozen/ORIGINAL.patch')],cwd=p,check=True,capture_output=True)
        require((p/'worker.py').read_bytes()==(ROOT/'frozen/candidate_worker.py').read_bytes(),'PATCH_APPLY')
        subprocess.run(['git','apply','--reverse',str(ROOT/'frozen/ORIGINAL.patch')],cwd=p,check=True,capture_output=True)
        require((p/'worker.py').read_bytes()==source,'PATCH_REVERSE')

def split_ids():
    decoder,_,_=science_modules();parts=read(ROOT/'frozen/split.json');binding=read(ROOT/'frozen/data-binding.json')
    require(set(parts)=={'train','validation'},'TRAIN_VALID_ONLY')
    ids={r:decoder.decode_index_bitset(v,source_count=60000) for r,v in parts.items()}
    require({r:decoder.sha256_json(v) for r,v in ids.items()}==binding['ordered_role_ids_sha256'],'ROLE_IDENTITY')
    require(len(ids['train'])==50000 and len(ids['validation'])==10000 and not set(ids['train'])&set(ids['validation']),'ROLE_SUPPORT')
    return ids

def environment():
    import importlib.metadata
    expected=read(ROOT/'frozen/environment.json')
    frozen=subprocess.run([sys.executable,'-m','pip','freeze','--exclude-editable'],capture_output=True,text=True,check=True).stdout.splitlines()
    actual={'versions':{n:importlib.metadata.version(n) for n in expected['versions']},
        'python':platform.python_version(),'system':platform.system(),'machine':platform.machine(),
        'threads':4,'interop_threads':1,'device':'cpu','pip_freeze':sorted(frozen)}
    require(all(actual[k]==expected[k] for k in actual),'FROZEN_CPU_RUNTIME_REQUIRED')
    actual.update(kernel=platform.release(),cpu_count=os.cpu_count(),runner_os=os.environ.get('RUNNER_OS'),
                  image_os=os.environ.get('ImageOS'),image_version=os.environ.get('ImageVersion'))
    return actual

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('REDIRECT_DENIED')

def download_train(destination):
    destination=Path(destination);destination.mkdir(mode=0o700,exist_ok=False)
    binding=read(ROOT/'frozen/data-binding.json');hashes=read(ROOT/'frozen/download-hashes.json')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    for name in ('train-images-idx3-ubyte','train-labels-idx1-ubyte'):
        url='https://raw.githubusercontent.com/zalandoresearch/fashion-mnist/'+binding['source_commit']+'/data/fashion/'+name+'.gz'
        with opener.open(url,timeout=120) as response:compressed=response.read(30_000_001)
        require(sha(compressed)==hashes[name+'.gz'],'COMPRESSED_TRAIN_HASH')
        raw=gzip.decompress(compressed)
        require(sha(raw)==hashes[name]==binding['raw_train_sha256'][name],'RAW_TRAIN_HASH')
        (destination/name).write_bytes(raw)
    return data_check(destination)

def data_check(data):
    from collections import Counter
    binding=read(ROOT/'frozen/data-binding.json')
    require(not data.is_symlink() and {p.name for p in data.iterdir()}==set(binding['raw_train_sha256']),'TRAIN_ONLY_DIRECTORY')
    for name,digest in binding['raw_train_sha256'].items():require(sha(regular(data/name,48_000_000))==digest,'TRAIN_HASH')
    raw=(data/'train-labels-idx1-ubyte').read_bytes()[8:]
    labels=[raw[i] for i in split_ids()['validation']]
    require(Counter(labels)=={i:1000 for i in range(10)},'CLASS_SUPPORT')
    return labels

def materialize(runtime,arm,synthetic):
    require(arm in ARMS,'ARM');runtime.mkdir(mode=0o700,exist_ok=False)
    names={'worker.py':arm+'_worker.py','baseline.py':'baseline.py','boundary.py':'boundary.py',
           'split.json':'split.json','realdata.py':'realdata.py','trusted_entry.py':'confirmation_entry.py','data_binding.json':'data-binding.json'}
    files={n:(ROOT/'frozen'/source).read_bytes() for n,source in names.items()}
    for name,raw in files.items():(runtime/name).write_bytes(raw)
    (runtime/'binding.json').write_bytes(canonical({'files':{n:sha(b) for n,b in files.items()},'synthetic':synthetic}))
    return sha((runtime/'binding.json').read_bytes())

def launch(runtime,data,out,seed,canary,binding_sha,synthetic=False):
    require(type(seed) is int and 1<=seed<2**31 and seed not in EXCLUDED,'SEED_DOMAIN')
    out.mkdir(mode=0o700,exist_ok=False);scratch=out/'scratch';scratch.mkdir()
    env={k:os.environ[k] for k in ('PATH','LANG') if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE='1',OMP_NUM_THREADS='4',OPENBLAS_NUM_THREADS='4',MKL_NUM_THREADS='4',
        TMPDIR=str(scratch),TORCH_HOME=str(scratch),CUDA_VISIBLE_DEVICES='')
    args=[sys.executable,'-I','-B',str(runtime/'trusted_entry.py'),'--runtime',str(runtime),'--site',site.getsitepackages()[0],
        '--data',str(data),'--output',str(out),'--canary',str(canary),'--seed',str(seed),'--binding-sha256',binding_sha]
    if synthetic:args.append('--synthetic')
    with (out/'private-worker.log').open('xb') as log:
        p=subprocess.run(args,cwd=runtime,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=900,check=False)
    require(p.returncode==0,'WORKER_FAILED_NO_RETRY')
    _,m,_=science_modules();m.safe_outputs(out,epochs=1 if synthetic else 5)
    return read(out/'result.json')

def hosted_context(workflow):
    expected={'GITHUB_REPOSITORY':REPOSITORY,'GITHUB_REPOSITORY_ID':str(REPOSITORY_ID),'GITHUB_REF':'refs/heads/main',
        'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1','GITHUB_REF_PROTECTED':'true','RUNNER_ENVIRONMENT':'github-hosted'}
    require(all(os.environ.get(k)==v for k,v in expected.items()),'PROTECTED_PUBLIC_MANUAL_FIRST_ATTEMPT')
    head=os.environ.get('GITHUB_SHA','')
    require(bool(re.fullmatch('[0-9a-f]{40}',head)) and os.environ.get('GITHUB_RUN_ID','').isdigit(),'RUN_IDENTITY')
    require(os.environ.get('GITHUB_WORKFLOW_REF')==REPOSITORY+'/.github/workflows/'+workflow+'@refs/heads/main','WORKFLOW_IDENTITY')
    actual=subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()
    require(actual==head,'CHECKOUT_IDENTITY')
    return {'repository':REPOSITORY,'repository_id':REPOSITORY_ID,'commit':head,'run_id':int(os.environ['GITHUB_RUN_ID']),
            'attempt':1,'workflow':workflow,'manifest_sha256':sha((ROOT/'MANIFEST.json').read_bytes())}
