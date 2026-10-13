"""Deterministic production batch path tests; fixture values only, no real fits."""
import errno
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import execute
from transport import BLOCKS,ARMS,read,durable,ROOT

class FinalizationTests(unittest.TestCase):
    def batch(self,base,scratch='empty',worker_error=False,cleanup_error=False):
        custody=base/'custody';custody.mkdir()
        durable(custody/'private-seeds.json',{'fixture':'NOT_CONFIRMATION'})
        manifest={'blocks':dict(zip(BLOCKS,[7101,7102,7103]))}
        runtimes={a:(base/a,'fixture-binding') for a in ARMS}
        identity=read(ROOT/'frozen/identity.json')
        def worker(rt,data,out,seed,canary,binding,synthetic):
            out.mkdir();(out/'private-worker.log').write_text('SYNTHETIC_FIXTURE')
            if scratch!='absent':
                (out/'scratch').mkdir()
                if scratch=='nonempty':
                    (out/'scratch/tmp').mkdir();(out/'scratch/tmp/file').write_text('temporary')
                    (out/'scratch/link').symlink_to(base/'external')
            if worker_error:raise RuntimeError('fixture worker failure')
            ep={'train_count':20,'validation':{'fixture':True},'train_order_sha256':str(seed)}
            return {'seed':seed,'seed_role':'SYNTHETIC_ENGINEERING','classification':'SYNTHETIC_ENGINEERING',
                'updates':1,'epochs':[ep],'final_validation':ep['validation'],'initial_state_sha256':str(seed),
                'worker_sha256':identity[('source' if rt.name=='baseline' else 'candidate')+'_sha256']}
        class Measurement:
            def verify_outputs(self,*args,**kwargs):return {'fixture':True}
        (base/'external').write_text('must survive')
        with patch('execute.launch',side_effect=worker),patch('execute.science_modules',return_value=(None,Measurement(),None)):
            if cleanup_error:
                with patch('finalize.shutil.rmtree',side_effect=OSError(errno.EACCES,'fixture cleanup')) as rm:
                    rm.avoids_symlink_attacks=True
                    return execute.batch(base,custody,manifest,'fixture',runtimes,[],synthetic=True)
            return execute.batch(base,custody,manifest,'fixture',runtimes,[],synthetic=True)
    def test_production_batch_finalization_empty_nonempty_absent(self):
        for mode in ('empty','nonempty','absent'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                p=Path(d);rows=self.batch(p,mode)
                self.assertEqual(len(rows),6)
                self.assertEqual(len(list((p/'custody').glob('*-RESULT.json'))),6)
                self.assertFalse(list((p/'custody').glob('*-FAILED.json')))
                self.assertFalse(list((p/'custody/fits').glob('*/scratch')))
                self.assertEqual((p/'external').read_text(),'must survive')
                self.assertTrue(all(r['status']=='SUCCEEDED' for r in rows))
    def test_genuine_worker_failure_is_retained_and_stops_next_cell(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            with self.assertRaisesRegex(RuntimeError,'fixture worker failure'):self.batch(p,'nonempty',True)
            self.assertEqual(len(list((p/'custody').glob('*-FAILED.json'))),1)
            self.assertFalse(list((p/'custody').glob('*-RESULT.json')))
            self.assertEqual(len(list((p/'custody').glob('*-STARTED.json'))),1)
            self.assertEqual(read(p/'custody/block-01-baseline-FAILED.json')['phase'],'SCIENTIFIC_EXECUTION_OR_VALIDATION')
    def test_cleanup_failure_is_distinct_and_never_invalidates_a_success_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            with self.assertRaises(OSError):self.batch(p,'nonempty',cleanup_error=True)
            self.assertFalse(list((p/'custody').glob('*-RESULT.json')))
            self.assertFalse((p/'custody/block-01-baseline-FAILED.json').exists())
            self.assertEqual(read(p/'custody/block-01-baseline-FINALIZATION-FAILED.json')['status'],'CUSTODY_FINALIZATION_FAILED')
    def test_scientific_failure_is_not_masked_by_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            with self.assertRaisesRegex(RuntimeError,'fixture worker failure'):self.batch(p,'nonempty',True,True)
            self.assertEqual(read(p/'custody/block-01-baseline-FAILED.json')['exception_type'],'RuntimeError')
            self.assertTrue((p/'custody/block-01-baseline-CLEANUP-FAILED.json').exists())

class ReplayTests(unittest.TestCase):
    def test_wall_clock_is_not_numerical_state(self):
        from qualify_recovery import verify_replay
        import copy
        first={'initial_state_sha256':'initial','state_sha256':'final',
            'epochs':[{'train_order_sha256':'order','train_loss':1.,'train_online_accuracy':.5}],
            'final_validation':{'evaluation_seconds':.1,'logits_sha256':'logits','accuracy':.5}}
        second=copy.deepcopy(first);second['final_validation']['evaluation_seconds']=.2
        verify_replay(first,second)
        second['final_validation']['accuracy']=.6
        with self.assertRaises(ValueError):verify_replay(first,second)
        second=copy.deepcopy(first);second['state_sha256']='different'
        with self.assertRaises(ValueError):verify_replay(first,second)
