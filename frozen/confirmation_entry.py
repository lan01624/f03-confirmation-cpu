"""Trusted entry: isolate BEFORE importing the exact reviewed candidate.

Only the trusted host handoff may invoke real mode after PI review/permit.
Synthetic mode is explicitly engineering-only and uses no external dataset.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import types

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def main():
    p=argparse.ArgumentParser()
    for name in ('runtime','site','data','output','canary','binding-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--seed',type=int,required=True);p.add_argument('--synthetic',action='store_true');a=p.parse_args()
    if not 1<=a.seed<2**31 or a.seed in (4901,4902,4903,5201,5202,5203,6101,6102,6103):raise ValueError('CONFIRMATION_SEED_DOMAIN')
    rt=Path(a.runtime);out=Path(a.output);h=lambda b:hashlib.sha256(b).hexdigest()
    raw=(rt/'binding.json').read_bytes()
    if h(raw)!=a.binding_sha256:raise ValueError('RUNTIME_BINDING')
    binding=json.loads(raw)
    if binding['synthetic']!=a.synthetic:raise ValueError('ROLE_MISMATCH')
    for name,digest in binding['files'].items():
        if '/' in name or (rt/name).is_symlink() or h((rt/name).read_bytes())!=digest:raise ValueError('EXECUTABLE_BYTES_CHANGED')
    boundary=load('trusted_boundary',rt/'boundary.py')
    read=[x for x in ['/usr','/lib','/lib64','/bin','/etc/ld.so.cache','/dev/null','/dev/urandom','/dev/random','/proc/cpuinfo','/proc/meminfo',sys.base_prefix,sys.prefix,a.site,a.runtime,a.data] if Path(x).exists()]
    if any(Path(a.canary).resolve().is_relative_to(Path(x).resolve()) for x in read+[a.output]):raise ValueError('PRIVATE_OVERLAP')
    boundary.restrict(read,[a.output]);checks={}
    try:Path(a.canary).read_bytes();checks['private_denied']=False
    except PermissionError:checks['private_denied']=True
    try:socket.socket();checks['network_denied']=False
    except PermissionError:checks['network_denied']=True
    try:subprocess.run(['/bin/true']);checks['process_denied']=False
    except PermissionError:checks['process_denied']=True
    if not all(checks.values()):raise RuntimeError('ISOLATION_FAILED')
    sys.path.insert(0,a.site)
    import numpy as np
    import torch
    from PIL import Image
    from torchvision.transforms import v2
    for name in ('aera_ml','aera_ml.evaluation'):
        pkg=types.ModuleType(name);pkg.__path__=[];sys.modules[name]=pkg
    decoder=load('aera_ml.evaluation.realdata',rt/'realdata.py')
    sys.modules['aera_ml.evaluation.realdata']=decoder
    base=load('trusted_base',rt/'baseline.py')
    candidate=load('reviewed_candidate',rt/'worker.py')  # first candidate import, AFTER isolation
    torch.set_num_threads(4);torch.set_num_interop_threads(1);torch.use_deterministic_algorithms(True)
    transform=v2.Compose([v2.ToImage(),v2.ToDtype(torch.float32,scale=True)])
    class Dataset:
        def __init__(self,images,labels):self.images=images;self.labels=labels;self.seen=[]
        def __len__(self):return len(self.labels)
        def __getitem__(self,i):
            self.seen.append(i);return transform(Image.fromarray(self.images[i],mode='L')),int(self.labels[i])
    if a.synthetic:
        images=np.arange(40*28*28,dtype=np.uint8).reshape(40,28,28);labels=np.arange(40)%10
        train=list(range(20));valid=list(range(20,40));epochs=1
    else:
        data=json.loads((rt/'data_binding.json').read_bytes());raw={}
        if set(data['raw_train_sha256'])!={'train-images-idx3-ubyte','train-labels-idx1-ubyte'}:raise ValueError('TRAIN_ROLE_ONLY')
        for name,digest in data['raw_train_sha256'].items():
            raw[name]=(Path(a.data)/name).read_bytes()
            if h(raw[name])!=digest:raise ValueError('TRAIN_HASH')
        im=raw['train-images-idx3-ubyte'];la=raw['train-labels-idx1-ubyte']
        if len(im)!=16+60000*784 or len(la)!=60008 or struct.unpack('>IIII',im[:16])!=(2051,60000,28,28) or struct.unpack('>II',la[:8])!=(2049,60000):raise ValueError('TRAIN_IDX_SHAPE')
        images=np.frombuffer(im,dtype=np.uint8,offset=16).reshape(60000,28,28);labels=np.frombuffer(la,dtype=np.uint8,offset=8)
        split=json.loads((rt/'split.json').read_bytes())
        # Use the existing bitset decoder, bundled separately and hash-bound.
        train=decoder.decode_index_bitset(split['train'],source_count=60000);valid=decoder.decode_index_bitset(split['validation'],source_count=60000)
        if len(train)!=50000 or len(valid)!=10000 or set(train)&set(valid) or len(set(train+valid))!=60000:raise ValueError('FROZEN_SPLIT')
        epochs=5
    dataset=Dataset(images,labels);start=time.time()
    r=candidate.train_only(torch,base,dataset,train,valid,a.seed,{'learning_rate':.001,'weight_decay':0.0},out,epochs)
    r.update(classification='SYNTHETIC_ENGINEERING' if a.synthetic else 'REAL_TRAIN_VALID_CONFIRMATION',seed_role='SYNTHETIC_ENGINEERING' if a.synthetic else 'CONFIRMATION',status='SUCCEEDED',isolation=checks,
        started_unix=start,completed_unix=time.time(),official_test_reads=0,worker_sha256=binding['files']['worker.py'])
    (out/'result.json').write_text(json.dumps(r,sort_keys=True,allow_nan=False)+'\n')

if __name__=='__main__':main()
