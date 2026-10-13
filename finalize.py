"""One cell's production finalization. Cleanup cannot retroactively invalidate success."""
import shutil
import stat
from transport import *

def cleanup(out):
    scratch=out/'scratch'
    try:mode=scratch.lstat().st_mode
    except FileNotFoundError:return
    # Do not follow symlinks; a worker cannot turn cleanup into an external deletion.
    require(stat.S_ISDIR(mode),'SCRATCH_NOT_DIRECTORY')
    require(shutil.rmtree.avoids_symlink_attacks,'FD_SAFE_CLEANUP_REQUIRED')
    shutil.rmtree(scratch)

def error_record(exc,phase,status):
    # Never stringify worker exceptions: they may contain seeds, paths or outcomes.
    return {'status':status,'phase':phase,'exception_type':type(exc).__name__,
        'errno':getattr(exc,'errno',None),'metrics':None,'retry':False}

def cell(custody,key,out,scientific_result):
    """Execute/validate scientific_result callback, clean scratch, then commit once."""
    durable(custody/(key+'-STARTED.json'),{'cell':key,'attempt':1,'status':'STARTED'})
    try:row=scientific_result()
    except BaseException as exc:
        failure=error_record(exc,'SCIENTIFIC_EXECUTION_OR_VALIDATION','INVALID_EXECUTION')
        try:cleanup(out)
        except BaseException as clean:
            durable(custody/(key+'-CLEANUP-FAILED.json'),error_record(clean,'SCRATCH_CLEANUP','CUSTODY_FINALIZATION_FAILED'))
        durable(custody/(key+'-FAILED.json'),failure)
        raise
    try:
        cleanup(out)
        row['artifacts']={f.name:sha(regular(f)) for f in out.iterdir()}
        row['evidence_id']='sha256:'+sha(canonical(row))
        durable(custody/(key+'-RESULT.json'),row)
    except BaseException as exc:
        # A durable write can be interrupted after the complete receipt is visible.
        # Never create a contradicting scientific FAILED receipt here.
        durable(custody/(key+'-FINALIZATION-FAILED.json'),error_record(exc,'CUSTODY_FINALIZATION','CUSTODY_FINALIZATION_FAILED'))
        raise
    return row
