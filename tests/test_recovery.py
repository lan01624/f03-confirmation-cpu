"""Recovery exclusion and custody cases contain synthetic fixture seeds only."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from transport import *
from recovery import protocol,binding,prior_seeds,custody_prior
from crypto import seal
from test_security import fixture
from authorize import validate_authority

class RecoveryTests(unittest.TestCase):
    def test_signed_recovery_identity_cannot_be_replayed_or_rebound(self):
        b,t,c,i,_=fixture()
        validate_authority(b,t,c,i,1000)
        for field in ('operation','protocol_sha256','prior_seed_manifest_sha256','original_run'):
            altered=copy.deepcopy(b);altered['authorization']['recovery'][field]='wrong'
            with self.assertRaises(Exception):validate_authority(altered,t,c,i,1000)
        with self.assertRaises(ValueError):binding('0'*64)
        with self.assertRaises(Exception):validate_authority(b,t,{**c,'workflow':'confirmation.yml'},i,1000)
    def fixture_prior(self):
        p=protocol();o=p['original_run']
        context={'repository':REPOSITORY,'repository_id':REPOSITORY_ID,'commit':o['commit'],'run_id':o['run_id'],
            'attempt':1,'workflow':'confirmation.yml','manifest_sha256':o['manifest_sha256']}
        permit={'schema':'R18B4_PUBLIC_PERMIT_V1','provenance':context,'science':p['science'],
            'authorization_sha256':o['authorization_sha256'],'recipient_sha256':o['recipient_sha256'],
            'marker':p['original_public_marker'],'run_seconds':900,'batch_seconds':7200,'attempt':1,'retries':0}
        return {'schema':'R18B4_PRIVATE_SEEDS_V1','seed_role':'CONFIRMATION','permit_sha256':sha(canonical(permit)),
            'blocks':dict(zip(BLOCKS,[8101,8102,8103]))}
    def test_prior_manifest_identity_domain_and_hash(self):
        m=self.fixture_prior();raw=canonical(m)+b'\n'
        self.assertEqual(prior_seeds(raw,sha(raw)),frozenset([8101,8102,8103]))
        with self.assertRaises(ValueError):prior_seeds(raw,'0'*64)
        for mutate in (lambda x:x.update(permit_sha256='0'*64),lambda x:x['blocks'].update({'block-01':4901}),
                       lambda x:x['blocks'].update({'block-01':8102})):
            changed=copy.deepcopy(m);mutate(changed);raw=canonical(changed)
            with self.assertRaises(ValueError):prior_seeds(raw,sha(raw))
    def test_real_draw_path_excludes_prior_and_historical_before_acceptance(self):
        import execute
        b,t,c,i,_=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);custody=p/'custody';custody.mkdir()
            durable(custody/'permit.json',{'provenance':c,'science':i})
            durable(custody/'claim.json',{'marker':MARKER,'provenance':c})
            durable(custody/'preflight.json',{'status':'SYNTHETIC_BOUNDARY_AND_RUNTIME_QUALIFIED'})
            b['authorization']['expires_unix']=10**12;durable(custody/'authority.json',b)
            # Stop at data_check, after fixture-only draw and manifest freeze; never train.
            with patch('execute.freeze',return_value=i),patch('execute.hosted_context',return_value=c),\
                 patch('execute.environment'),patch('execute.custody_prior',return_value={8101,8102,8103}),\
                 patch('execute.secrets.randbelow',side_effect=[4900,8100,9100,9100,9101,9102]) as draw,\
                 patch('execute.data_check',side_effect=RuntimeError('fixture stop before fits')):
                with self.assertRaisesRegex(RuntimeError,'fixture stop'):execute.run(p)
                self.assertEqual(list(read(custody/'private-seeds.json')['blocks'].values()),[9101,9102,9103])
                self.assertEqual(draw.call_count,6)
    def test_scratch_never_enters_encrypted_scientific_custody_even_on_cleanup_failure(self):
        from verify_custody import decrypt
        from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
        b,t,c,i,key=fixture()
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'GITHUB_ACTIONS':''}):
            p=Path(d);custody=p/'custody';scratch=custody/'fits/block-01-baseline/scratch';scratch.mkdir(parents=True)
            (scratch/'unexpected.tmp').write_text('DISCARD_SYNTHETIC_TEMP_ONLY')
            (scratch/'link').symlink_to(p/'outside')
            (custody/'block-01-baseline-FINALIZATION-FAILED.json').write_text('{"status":"CUSTODY_FINALIZATION_FAILED"}')
            provenance={**c,'science':i,'recipient_sha256':t['recipient_sha256'],'authorization_sha256':sha(canonical(b))}
            seal(custody,p/'encrypted',t['recipient_public_pem'].encode(),provenance)
            keyfile=p/'fixture-key.pem';keyfile.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
            envelope=p/'encrypted/encrypted-custody.json'
            decrypt(envelope,p/'decrypted',keyfile,provenance,sha(envelope.read_bytes()))
            self.assertFalse((p/'decrypted/fits').exists())
            self.assertTrue((p/'decrypted/block-01-baseline-FINALIZATION-FAILED.json').exists())
