import ast
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from transport import freeze,patch_parity,split_ids,science_modules,read,sha,canonical,EXCLUDED,ROOT

class StaticTests(unittest.TestCase):
    def test_exact_scientific_identities_and_patch(self):
        identity=freeze();patch_parity()
        self.assertEqual(identity['source_sha256'],'2bf52f7c7cd8505d4218e6eeb444f72fdfb46cc8cd609db9b493fcd23df9be1e')
        self.assertEqual(identity['candidate_sha256'],'aa63dd08702d3c9b27103edfdfbde0123ee4ea6bbe63a4b96cd4931a88f643bc')
        self.assertEqual(identity['patch_sha256'],'f621141f4b1d3420f7723efdf42af7bfec8660a829be8478b332e8c2f27f6691')
    def test_exact_two_trusted_entry_substitutions(self):
        raw=(ROOT/'frozen/original_entry.py').read_bytes()
        replacements=[(b"if a.seed not in (6101,6102,6103):raise ValueError('DEV_SEED_ONLY')",b"if not 1<=a.seed<2**31 or a.seed in (4901,4902,4903,5201,5202,5203,6101,6102,6103):raise ValueError('CONFIRMATION_SEED_DOMAIN')"),(b"classification='SYNTHETIC_ENGINEERING' if a.synthetic else 'REAL_TRAIN_VALID_DEV',status='SUCCEEDED'",b"classification='SYNTHETIC_ENGINEERING' if a.synthetic else 'REAL_TRAIN_VALID_CONFIRMATION',seed_role='SYNTHETIC_ENGINEERING' if a.synthetic else 'CONFIRMATION',status='SUCCEEDED'")]
        for before,after in replacements:self.assertEqual(raw.count(before),1);raw=raw.replace(before,after)
        self.assertEqual(raw,(ROOT/'frozen/confirmation_entry.py').read_bytes())
    def test_fixed_split(self):
        ids=split_ids();self.assertEqual(len(ids['train']),50000);self.assertEqual(len(ids['validation']),10000)
        self.assertEqual(set(ids['train'])|set(ids['validation']),set(range(60000)))
    def test_no_test_capable_baseline_entry(self):
        t=ast.parse((ROOT/'frozen/baseline.py').read_bytes())
        self.assertEqual({n.name for n in t.body if isinstance(n,ast.FunctionDef)},{'_model','_state_dict_hash','_evaluate','_loader'})
    def test_all_prior_seeds_and_incomplete_pairs_rejected(self):
        _,_,s=science_modules()
        for seed in EXCLUDED:
            m={'schema':'R18B4_PRIVATE_SEEDS_V1','seed_role':'CONFIRMATION','permit_sha256':'engineering-only',
                'blocks':dict(zip(s.BLOCKS,[seed,7102,7103]))}
            with self.assertRaises(ValueError):s.validate_seeds(m,'engineering-only')
        with self.assertRaises(ValueError):s.aggregate([])
    def test_n3_rule_and_zero_variance_refusal(self):
        _,_,s=science_modules()
        rows=[]
        for i,block in enumerate(s.BLOCKS):
            for arm in ('baseline','candidate'):
                delta=0 if arm=='baseline' else .1*(i+1)
                rows.append({'block':block,'arm':arm,'status':'SUCCEEDED','role':'CONFIRMATION','evidence_id':block+arm,
                    'initial_state_sha256':block,'train_orders':[block],
                    'metrics':{**{k:delta for k in ('primary_recall_5_6','accuracy','macro_recall','cross_entropy')},'per_class_recall':[delta]*10}})
        r=s.aggregate(rows);self.assertEqual(r['status'],'INCONCLUSIVE')
        for row in rows:row['metrics']['primary_recall_5_6']=0
        self.assertEqual(s.aggregate(rows)['status'],'INCONCLUSIVE')
        rows[1]['train_orders']=['mismatched']
        with self.assertRaises(ValueError):s.aggregate(rows)
    def test_production_disabled(self):
        self.assertIs(read(ROOT/'activation.json')['real_execution_authorized'],False)
    def test_synthetic_has_no_real_draw_or_data_download(self):
        tree=ast.parse((ROOT/'qualify.py').read_bytes())
        names={n.id for n in ast.walk(tree) if isinstance(n,ast.Name)}
        self.assertFalse(names & {'secrets','download_train','randbelow'})

if __name__=='__main__':unittest.main()
