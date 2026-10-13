"""Trusted TRAIN/VALID-only F03 adapter. Never call baseline.execute/_train_seed.

Executed from an exact source-bound Compiler worktree. No FashionMNIST loader:
its availability checks can inspect TEST names. Decode only approved TRAIN IDX.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


def digest(raw):return hashlib.sha256(raw).hexdigest()


def controls(root):
    result={}
    for key,allowed in [('learning_rate',(0.001,0.003)),('weight_decay',(0.0,0.0001))]:
        obj=json.loads((Path(root)/(key+'.json')).read_bytes())
        if set(obj)!={key} or type(obj[key]) not in (float,int) or obj[key] not in allowed:
            raise ValueError('FACTOR_CONFIG_INVALID')
        result[key]=obj[key]
    return result


def boundary(runtime,site,data,output,canary):
    spec=importlib.util.spec_from_file_location('boundary',Path(runtime)/'boundary.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    read=[p for p in ['/usr','/lib','/lib64','/bin','/etc/ld.so.cache','/dev/null','/dev/urandom',
        '/dev/random','/proc/cpuinfo','/proc/meminfo',sys.base_prefix,sys.prefix,site,runtime,data] if Path(p).exists()]
    private=Path(canary).resolve()
    if any(private.is_relative_to(Path(p).resolve()) for p in read+[output]):raise ValueError('PRIVATE_OVERLAP')
    m.restrict(read,[output]);checks={}
    try:Path(canary).read_bytes();checks['official_test_capability_denied']=False
    except PermissionError:checks['official_test_capability_denied']=True
    try:socket.socket();checks['network_denied']=False
    except PermissionError:checks['network_denied']=True
    try:subprocess.run(['/bin/true']);checks['process_denied']=False
    except PermissionError:checks['process_denied']=True
    if not all(checks.values()):raise RuntimeError('BOUNDARY_NOT_QUALIFIED')
    return checks


def train_only(torch,base,dataset,train,valid,seed,settings,output,epochs=5):
    torch.manual_seed(seed);model=base._model(torch).to('cpu')
    initial=base._state_dict_hash(torch,model);loss_fn=torch.nn.CrossEntropyLoss()
    # Research patch: add Nesterov momentum to SGD to accelerate optimization for hard classes.
    optimizer=torch.optim.SGD(model.parameters(),lr=settings['learning_rate'],momentum=0.9,nesterov=True,weight_decay=settings['weight_decay'])
    loader=base._loader(torch,dataset,train,shuffle=True,seed=seed)
    validation=base._loader(torch,dataset,valid,shuffle=False,seed=seed)
    rows=[];updates=0;start=time.monotonic()
    for epoch in range(1,epochs+1):
        model.train();total=0.;correct=0;count=0;t0=time.monotonic()
        if hasattr(dataset,'seen'):dataset.seen.clear()
        for x,y in loader:
            logits=model(x);loss=loss_fn(logits,y)
            if not bool(torch.isfinite(loss)):raise RuntimeError('NONFINITE_TRAIN_LOSS')
            optimizer.zero_grad();loss.backward();optimizer.step();updates+=1
            n=y.numel();count+=n;total+=float(loss.item())*n;correct+=int((logits.argmax(1)==y).sum())
        order=base.sha256_json(dataset.seen) if hasattr(dataset,'seen') else None
        # Capture the existing validation forward outputs; no second inference.
        predictions=[];captured=[]
        def capture(module,args,logits):
            predictions.extend(int(x) for x in logits.argmax(1).tolist());captured.append(logits.detach().cpu())
        hook=model.register_forward_hook(capture)
        try:v=base._evaluate(torch,model,validation,loss_fn)
        finally:hook.remove()
        if base.sha256_json(predictions)!=v['prediction_sha256']:raise ValueError('PREDICTION_CAPTURE')
        prediction_path=Path(output)/('validation-predictions-epoch'+str(epoch)+'.json')
        prediction_path.write_bytes(json.dumps(predictions,separators=(',',':')).encode())
        import numpy as np
        logits_path=Path(output)/('validation-logits-epoch'+str(epoch)+'.npy')
        np.save(logits_path,torch.cat(captured).numpy(),allow_pickle=False)
        v['logits_sha256']=digest(logits_path.read_bytes())
        rows.append({'epoch':epoch,'train_loss':total/count,'train_online_accuracy':correct/count,
            'train_count':count,'train_order_sha256':order,'validation':v,'updates':updates,'seconds':time.monotonic()-t0})
    checkpoint=Path(output)/'checkpoint.pt';torch.save(model.state_dict(),checkpoint)
    return {'seed':seed,'seed_role':'SEARCH_DEV','epochs':rows,'updates':updates,
        'initial_state_sha256':initial,'state_sha256':base._state_dict_hash(torch,model),
        'checkpoint_sha256':digest(checkpoint.read_bytes()),'checkpoint_bytes':checkpoint.stat().st_size,
        'final_validation':rows[-1]['validation'],'training_seconds':time.monotonic()-start,
        'settings':settings,'scientific_promotion':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('--runtime',required=True);p.add_argument('--site',required=True)
    p.add_argument('--data',required=True);p.add_argument('--output',required=True);p.add_argument('--canary',required=True)
    p.add_argument('--seed',type=int,required=True);p.add_argument('--synthetic',action='store_true');a=p.parse_args()
    if a.seed not in (5201,5202,5203):raise ValueError('UNAPPROVED_DEV_SEED')
    runtime=Path(a.runtime);out=Path(a.output);sys.path[:0]=[str(runtime),a.site]
    checks=boundary(str(runtime),a.site,a.data,a.output,a.canary)
    import torch
    import numpy as np
    from PIL import Image
    from torchvision.transforms import v2
    import baseline as base
    torch.set_num_threads(4);torch.set_num_interop_threads(1);torch.use_deterministic_algorithms(True)
    settings=controls(runtime)
    transform=v2.Compose([v2.ToImage(),v2.ToDtype(torch.float32,scale=True)])
    class Dataset:
        def __init__(self,images,labels):self.images=images;self.labels=labels;self.seen=[]
        def __len__(self):return len(self.labels)
        def __getitem__(self,i):
            self.seen.append(i)
            return transform(Image.fromarray(self.images[i],mode='L')),int(self.labels[i])
    if a.synthetic:
        images=np.arange(16*28*28,dtype=np.uint8).reshape(16,28,28);labels=np.arange(16)%10
        dataset=Dataset(images,labels);train=list(range(8));valid=list(range(8,16));epochs=1
        data_binding={'classification':'SYNTHETIC_ENGINEERING_NOT_REAL_FIT'}
    else:
        binding=json.loads((runtime/'data_binding.json').read_bytes());raw={}
        for name,h in binding['raw_train_sha256'].items():
            if name not in ('train-images-idx3-ubyte','train-labels-idx1-ubyte'):raise ValueError('DATA_ROLE_DENIED')
            raw[name]=(Path(a.data)/name).read_bytes()
            if digest(raw[name])!=h:raise ValueError('RAW_DATA_HASH')
        im=raw['train-images-idx3-ubyte'];la=raw['train-labels-idx1-ubyte']
        if struct.unpack('>IIII',im[:16])!=(2051,60000,28,28) or struct.unpack('>II',la[:8])!=(2049,60000):raise ValueError('IDX_SHAPE')
        images=np.frombuffer(im,dtype=np.uint8,offset=16).reshape(60000,28,28);labels=np.frombuffer(la,dtype=np.uint8,offset=8)
        dataset=Dataset(images,labels);split=json.loads((runtime/'split.json').read_bytes())
        from aera_ml.evaluation.realdata import decode_index_bitset
        train=decode_index_bitset(split['train'],source_count=60000)
        valid=decode_index_bitset(split['validation'],source_count=60000)
        if len(train)!=50000 or len(valid)!=10000 or set(train)&set(valid) or len(set(train+valid))!=60000:raise ValueError('SPLIT_INVALID')
        epochs=5;data_binding=binding
    started=time.time();result=train_only(torch,base,dataset,train,valid,a.seed,settings,out,epochs)
    result.update({'classification':'SYNTHETIC_ENGINEERING' if a.synthetic else 'REAL_TRAIN_VALID_DEV',
        'started_unix':started,'completed_unix':time.time(),'isolation':checks,'data_binding':data_binding,
        'official_test_constructed':False,'official_test_read':False,'status':'SUCCEEDED'})
    (out/'result.json').write_text(json.dumps(result,sort_keys=True,allow_nan=False)+'\n')


if __name__=='__main__':main()
