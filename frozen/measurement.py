import hashlib, json, stat
sha256=lambda raw:hashlib.sha256(raw).hexdigest()

def safe_outputs(out,*,epochs):
    expected={'scratch','private-worker.log','result.json','checkpoint.pt'}|{f'validation-{kind}-epoch{i}.{ext}' for i in range(1,epochs+1) for kind,ext in [('predictions','json'),('logits','npy')]}
    if {p.name for p in out.iterdir()}!=expected:raise ValueError('UNEXPECTED_WORKER_OUTPUT')
    for p in out.iterdir():
        s=p.lstat()
        if p.name=='scratch':
            if not stat.S_ISDIR(s.st_mode):raise ValueError('UNSAFE_OUTPUT_OBJECT')
            continue  # never traverse, read, trust or archive scratch contents
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>128*1024*1024:raise ValueError('UNSAFE_OUTPUT_OBJECT')


def metrics(logits,labels):
    import numpy as np
    import torch
    x=np.asarray(logits);y=np.asarray(labels)
    if x.shape!=(len(y),10) or x.dtype!=np.float32 or not np.isfinite(x).all() or set(y.tolist())!=set(range(10)):raise ValueError('VALIDATION_SUPPORT_OR_FORMAT')
    pred=x.argmax(1);recall=[float((pred[y==i]==i).mean()) for i in range(10)]
    # Fixed unweighted assessment, independently of candidate training loss.
    loss=sum(float(torch.nn.functional.cross_entropy(torch.from_numpy(x[i:i+64]),torch.tensor(y[i:i+64],dtype=torch.long)).item())*len(y[i:i+64]) for i in range(0,len(y),64))/len(y)
    return {'primary_recall_5_6':sum(recall[5:7])/2,'accuracy':float((pred==y).mean()),'macro_recall':sum(recall)/10,'cross_entropy':loss,'per_class_recall':recall}


def verify_outputs(out,result,labels,*,epochs=5):
    import numpy as np
    from aera_ml.evaluation.realdata import sha256_json
    if result.get('official_test_reads')!=0 or not all(result.get('isolation',{}).values()) or len(result['epochs'])!=epochs:raise ValueError('EXECUTION_CONFORMANCE')
    for i,e in enumerate(result['epochs'],1):
        raw=(out/f'validation-logits-epoch{i}.npy').read_bytes();pred=(out/f'validation-predictions-epoch{i}.json').read_bytes();v=e['validation']
        if sha256(raw)!=v['logits_sha256'] or sha256(pred)!=v['prediction_sha256'] or sha256_json(labels)!=v['ground_truth_sha256']:raise ValueError('OUTPUT_IDENTITY')
        x=np.load(out/f'validation-logits-epoch{i}.npy',allow_pickle=False)
        if x.shape!=(len(labels),10) or x.argmax(1).tolist()!=json.loads(pred):raise ValueError('VALIDATION_ROW_ORDER')
        m=metrics(x,labels)
        if m['accuracy']!=v['accuracy']:raise ValueError('METRIC_INTEGRITY')
    if sha256((out/'checkpoint.pt').read_bytes())!=result['checkpoint_sha256']:raise ValueError('CHECKPOINT_IDENTITY')
    return m
