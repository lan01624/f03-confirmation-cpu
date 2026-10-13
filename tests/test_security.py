"""Synthetic signatures/keys only; never use these fixtures as evaluator authority."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from transport import *
from crypto import *
from authorize import validate_authority,api,claim,protections

def fixture(auth_changes=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    pi=Ed25519PrivateKey.generate();ev=Ed25519PrivateKey.generate();rsa=generate_private_key(public_exponent=65537,key_size=3072)
    pem=lambda k:k.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()
    trust={'pi_signing_public_pem':pem(pi.public_key()),'evaluator_signing_public_pem':pem(ev.public_key()),
        'pi_signing_sha256':fingerprint(pi.public_key()),'evaluator_signing_sha256':fingerprint(ev.public_key()),
        'evaluator_login':OWNER_LOGIN,'evaluator_id':OWNER_ID,'recipient_public_pem':pem(rsa.public_key()),'recipient_sha256':fingerprint(rsa.public_key())}
    context={'repository':REPOSITORY,'repository_id':REPOSITORY_ID,'commit':'1'*40,'run_id':123,'attempt':1,
        'workflow':'confirmation.yml','manifest_sha256':'2'*64}
    identity=read(ROOT/'frozen/identity.json')
    reservation={'schema':'R18B4_PRIVATE_DELEGATION_V1','science':identity,'public_repository_id':REPOSITORY_ID,
        'public_commit':context['commit'],'old_marker':'refs/tags/r18b4-f03-confirmation-v1-consumed','old_marker_commit':'3'*40,
        'private_delegation_commit':'4'*40,'status':'OLD_ROUTE_RESERVED_NO_FITS'}
    auth={'schema':'R18B4_PUBLIC_AUTHORIZATION_V2','operation':OPERATION,'owner_id':OWNER_ID,'human_review':'OWNER_OPERATED','independent_human_review':False,'provenance':context,'science':identity,'evaluator_login':OWNER_LOGIN,
        'evaluator_id':OWNER_ID,'owner_login':OWNER_LOGIN,'recipient_sha256':trust['recipient_sha256'],'reservation_sha256':sha(canonical(reservation)),
        'expires_unix':2000,'approval_digest':'5'*64,'accepts_n3_limit':True,'off_host_owner_key_attestation':True,'transport_amendment_approved':True}
    if auth_changes:auth.update(auth_changes)
    sign=lambda k,v:base64.b64encode(k.sign(canonical(v))).decode()
    bundle={'authorization':auth,'pi_signature':sign(pi,auth),'evaluator_signature':sign(ev,auth),
        'reservation':reservation,'reservation_pi_signature':sign(pi,reservation)}
    return bundle,trust,context,identity,rsa

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=fixture()
    def test_signed_authority_and_replay_refusal(self):
        b,t,c,i,_=copy.deepcopy(self.fixture[:4])+self.fixture[4:]
        validate_authority(b,t,c,i,1000)
        for field,value in [('run_id',124),('attempt',2),('repository_id',1),('commit','f'*40)]:
            changed=copy.deepcopy(c);changed[field]=value
            with self.assertRaises(ValueError):validate_authority(b,t,changed,i,1000)
        b['authorization']['recipient_sha256']='0'*64
        with self.assertRaises(Exception):validate_authority(b,t,c,i,1000)
    def test_signature_owner_identity_expiry_and_reservation(self):
        b,t,c,i,_=self.fixture
        for mutate in (lambda v:v['authorization'].update(evaluator_login='another-person'),
                       lambda v:v.update(evaluator_signature=v['pi_signature']),
                       lambda v:v['reservation'].update(status='UNRESERVED'),
                       lambda v:v['authorization'].update(transport_amendment_approved=False)):
            v=copy.deepcopy(b);mutate(v)
            with self.assertRaises(Exception):validate_authority(v,t,c,i,1000)
        with self.assertRaises(ValueError):validate_authority(b,t,c,i,3000)
    def test_token_scope_cannot_read_private_or_do_other_mutations(self):
        for method,path,body,token in [('GET','/git/ref/heads/main',None,'synthetic'),('POST','/issues',{},'synthetic'),
            ('GET','/../../Aera-ML',None,None),('DELETE','/git/refs/tags/anything',None,'synthetic')]:
            with self.assertRaises(ValueError):api(method,path,body,token)
    def test_marker_uncertainty_is_terminal_locally(self):
        b,t,c,i,_=self.fixture
        with tempfile.TemporaryDirectory() as d:
            private=Path(d);custody=private/'custody';custody.mkdir()
            durable(custody/'authority.json',b);durable(custody/'trust.json',t)
            with patch('authorize.freeze',return_value=i),patch('authorize.hosted_context',return_value=c),\
                 patch('authorize.validate_authority',return_value=b['authorization']),patch('authorize.protections'),\
                 patch.dict(os.environ,{'GITHUB_TOKEN':'synthetic-only'}),patch('authorize.api',side_effect=TimeoutError) as call:
                with self.assertRaises(TimeoutError):claim(private)
                with self.assertRaises(FileExistsError):claim(private)
                self.assertEqual(call.call_count,1)
    def test_owner_protections_accept_and_reject_misconfiguration(self):
        auth=self.fixture[0]['authorization']
        good={'can_admins_bypass':False,'protection_rules':[{'type':'required_reviewers','prevent_self_review':False,
            'reviewers':[{'type':'User','reviewer':{'id':OWNER_ID,'login':OWNER_LOGIN}}]}],
            'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}}
        branch={'protected':True,'commit':{'sha':'1'*40},'protection':{'required_status_checks':{
            'enforcement_level':'everyone','checks':[{'context':'owner-transport-checks','app_id':15368}]}}}
        for change in ('good','bypass','self','branch','tag','extra_reviewer','wrong_id','wrong_login','unprotected','missing_check','wrong_app'):
            v=copy.deepcopy(good);br=copy.deepcopy(branch)
            if change=='bypass':v['can_admins_bypass']=True
            if change=='self':v['protection_rules'][0]['prevent_self_review']=True
            if change=='extra_reviewer':v['protection_rules'][0]['reviewers']*=2
            if change=='wrong_id':v['protection_rules'][0]['reviewers'][0]['reviewer']['id']=99
            if change=='wrong_login':v['protection_rules'][0]['reviewers'][0]['reviewer']['login']='another-person'
            if change=='unprotected':br['protected']=False
            if change=='missing_check':br['protection']['required_status_checks']['checks']=[]
            if change=='wrong_app':br['protection']['required_status_checks']['checks'][0]['app_id']=1
            policies={'branch_policies':[{'name':'main' if change!='branch' else '*','type':'tag' if change=='tag' else 'branch'}]}
            with self.subTest(change=change),patch('authorize.api',side_effect=[{'id':REPOSITORY_ID,'visibility':'public'},
                {'object':{'sha':'1'*40}},br,v,policies]):
                if change=='good':protections(auth)
                else:
                    with self.assertRaises(ValueError):protections(auth)
    def test_signed_false_identity_roles_and_disclosure_rejected(self):
        for field,value in [('schema','R18B4_PUBLIC_AUTHORIZATION_V1'),('operation','THIRD_PARTY_REVIEW'),
            ('owner_login','another-person'),('owner_id',99),('evaluator_id',99),('evaluator_login','another-person'),
            ('human_review','INDEPENDENT'),('independent_human_review',True),('off_host_owner_key_attestation',False)]:
            with self.subTest(field=field):
                b,t,c,i,_=fixture({field:value})
                with self.assertRaises(ValueError):validate_authority(b,t,c,i,1000)
    def test_encrypt_decrypt_complete_custody_and_tamper(self):
        from verify_custody import decrypt
        from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
        b,t,c,i,key=self.fixture
        # Only fixture decryption is mocked off host. Production guard remains tested.
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'GITHUB_ACTIONS':''}):
            p=Path(d);custody=p/'custody';custody.mkdir();(custody/'private-log.txt').write_text('SYNTHETIC_CONFIDENTIAL_TEST_VALUE')
            provenance={**c,'science':i,'recipient_sha256':t['recipient_sha256'],'authorization_sha256':sha(canonical(b))}
            seal(custody,p/'encrypted',t['recipient_public_pem'].encode(),provenance)
            envelope=p/'encrypted/encrypted-custody.json';self.assertNotIn(b'SYNTHETIC_CONFIDENTIAL_TEST_VALUE',envelope.read_bytes())
            keyfile=p/'test-only.pem';keyfile.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
            decrypt(envelope,p/'decrypted',keyfile,provenance,sha(envelope.read_bytes()))
            self.assertEqual((p/'decrypted/private-log.txt').read_bytes(),(custody/'private-log.txt').read_bytes())
            changed={**provenance,'attempt':2}
            with self.assertRaises(ValueError):decrypt(envelope,p/'bad',keyfile,changed,sha(envelope.read_bytes()))
            with self.assertRaises(ValueError):decrypt(envelope,p/'bad',keyfile,provenance,'0'*64)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):
                with self.assertRaisesRegex(ValueError,'OFF_HOST_ONLY'):
                    decrypt(envelope,p/'forbidden',keyfile,provenance,sha(envelope.read_bytes()))
    def test_execution_cannot_draw_before_claim(self):
        import execute
        b,t,c,i,_=self.fixture
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'custody').mkdir();durable(p/'custody/permit.json',{'provenance':c,'science':i})
            real_read=execute.read
            def fake_read(path):
                if Path(path).name=='activation.json':return {'real_execution_authorized':True}
                return real_read(path)
            with patch('execute.freeze',return_value=i),patch('execute.environment'),patch('execute.hosted_context',return_value=c),\
                patch('execute.read',side_effect=fake_read),patch('execute.secrets.randbelow') as draw:
                with self.assertRaises(FileNotFoundError):execute.run(p)
                draw.assert_not_called()

if __name__=='__main__':unittest.main()
