"""Fail-closed signed transport authority and atomic public marker claim."""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
from transport import *
from crypto import signature_verify,recipient,fingerprint

ENVIRONMENT='r18b4-independent-evaluator'

def validate_authority(bundle,trust,context,identity,now):
    require(set(bundle)=={'authorization','pi_signature','evaluator_signature','reservation','reservation_pi_signature'},'AUTHORIZATION_SCHEMA')
    auth=bundle['authorization'];reservation=bundle['reservation']
    expected={'schema','provenance','science','evaluator_login','evaluator_id','owner_login','recipient_sha256',
        'reservation_sha256','expires_unix','approval_digest','accepts_n3_limit','independent_key_attestation','transport_amendment_approved'}
    require(set(auth)==expected,'AUTHORIZATION_FIELDS')
    require(auth['schema']=='R18B4_PUBLIC_AUTHORIZATION_V1' and auth['provenance']==context and auth['science']==identity,'SIGNED_RUN_SCIENCE_BINDING')
    require(auth['owner_login']=='lan01624' and auth['evaluator_login']==trust['evaluator_login']!='lan01624','INDEPENDENT_HUMAN_REQUIRED')
    require(type(auth['evaluator_id']) is int and auth['evaluator_id']==trust['evaluator_id'],'EVALUATOR_IDENTITY')
    require(type(auth['expires_unix']) is int and now<auth['expires_unix']<=now+86400,'AUTHORIZATION_EXPIRY')
    require(auth['accepts_n3_limit'] is True and auth['independent_key_attestation'] is True and auth['transport_amendment_approved'] is True,'SUBSTANTIVE_APPROVAL')
    pi=signature_verify(auth,bundle['pi_signature'],trust['pi_signing_public_pem'].encode())
    evaluator=signature_verify(auth,bundle['evaluator_signature'],trust['evaluator_signing_public_pem'].encode())
    require(pi!=evaluator and pi==trust['pi_signing_sha256'] and evaluator==trust['evaluator_signing_sha256'],'DISTINCT_SIGNERS')
    require(auth['recipient_sha256']==trust['recipient_sha256'],'EVALUATOR_RECIPIENT')
    recipient(trust['recipient_public_pem'].encode(),auth['recipient_sha256'])
    require(auth['reservation_sha256']==sha(canonical(reservation)),'RESERVATION_BINDING')
    signature_verify(reservation,bundle['reservation_pi_signature'],trust['pi_signing_public_pem'].encode())
    require(set(reservation)=={'schema','science','public_repository_id','public_commit','old_marker','old_marker_commit','private_delegation_commit','status'},'RESERVATION_FIELDS')
    require(reservation['schema']=='R18B4_PRIVATE_DELEGATION_V1' and reservation['status']=='OLD_ROUTE_RESERVED_NO_FITS' and
        reservation['science']==identity and reservation['public_repository_id']==REPOSITORY_ID and
        reservation['public_commit']==context['commit'] and reservation['old_marker']=='refs/tags/r18b4-f03-confirmation-v1-consumed','PRIVATE_ROUTE_NOT_RESERVED')
    for k in ('old_marker_commit','private_delegation_commit'):
        require(bool(re.fullmatch('[0-9a-f]{40}',reservation[k])),'PRIVATE_RESERVATION_COMMIT')
    require(bool(re.fullmatch('[0-9a-f]{64}',auth['approval_digest'])),'REVIEWER_DIGEST')
    return auth

def api(method,path,body=None,token=None):
    # Private repository endpoints cannot be expressed. Token only for this marker.
    allowed_reads={'','/git/ref/heads/main','/environments/'+ENVIRONMENT,
        '/environments/'+ENVIRONMENT+'/deployment-branch-policies','/git/ref/'+MARKER[5:]}
    require((method=='GET' and path in allowed_reads and token is None) or
        (method=='POST' and path=='/git/refs' and body=={'ref':MARKER,'sha':os.environ['GITHUB_SHA']} and bool(token)),'API_SCOPE_DENIED')
    headers={'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'}
    if token:headers['Authorization']='Bearer '+token
    req=urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+path,method=method,headers=headers,
        data=None if body is None else canonical(body))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(req,timeout=30) as r:
        require(r.status==(201 if method=='POST' else 200),'API_STATUS');return json.load(r)

def protections(auth):
    repo=api('GET','');require(repo['id']==REPOSITORY_ID and repo['visibility']=='public','PUBLIC_REPOSITORY_IDENTITY')
    require(api('GET','/git/ref/heads/main')['object']['sha']==auth['provenance']['commit'],'MAIN_MOVED')
    env=api('GET','/environments/'+ENVIRONMENT)
    require(env.get('can_admins_bypass') is False,'ADMIN_BYPASS_MUST_BE_DISABLED')
    rule=next((r for r in env['protection_rules'] if r['type']=='required_reviewers'),None)
    require(rule is not None and rule.get('prevent_self_review') is True,'SELF_REVIEW_MUST_BE_DISABLED')
    require(any(r['type']=='User' and r['reviewer']['id']==auth['evaluator_id'] for r in rule['reviewers']),'REQUIRED_EVALUATOR')
    require(all(r['type']=='User' and r['reviewer']['id']==auth['evaluator_id'] for r in rule['reviewers']),'EVALUATOR_ONLY_REVIEWER')
    require(env['deployment_branch_policy']=={'protected_branches':False,'custom_branch_policies':True},'MAIN_ONLY_DEPLOYMENT_POLICY')
    policy=api('GET','/environments/'+ENVIRONMENT+'/deployment-branch-policies')['branch_policies']
    require(len(policy)==1 and policy[0]['name']=='main' and policy[0]['type']=='branch','MAIN_ONLY_ENVIRONMENT')
    return {'environment':env,'branch_policies':policy}

def prepare(private,trust_path):
    identity=freeze();context=hosted_context('confirmation.yml');activation=read(ROOT/'activation.json')
    require(activation['real_execution_authorized'] is True and activation['status']=='PROSPECTIVELY_APPROVED','PRODUCTION_DISABLED')
    require(os.environ.get('GITHUB_ACTOR')=='lan01624' and os.environ.get('GITHUB_TRIGGERING_ACTOR')=='lan01624','OWNER_DISPATCH_REQUIRED')
    trust=read(trust_path);bundle=json.loads(os.environ['R18B4_SIGNED_AUTHORIZATION'])
    auth=validate_authority(bundle,trust,context,identity,time.time())
    import hmac
    require(hmac.compare_digest(auth['approval_digest'],os.environ.get('R18B4_REVIEWER_APPROVAL_SHA256','')),'REVIEWER_CONTROLLED_DIGEST')
    require(not private.exists() and not private.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(private.resolve()),'FRESH_EXTERNAL_CUSTODY')
    proof=protections(auth)
    private.mkdir(mode=0o700);custody=private/'custody';custody.mkdir(mode=0o700)
    durable(custody/'authority.json',bundle);durable(custody/'trust.json',trust);durable(custody/'protections.json',proof)
    durable(custody/'permit.json',{'schema':'R18B4_PUBLIC_PERMIT_V1','provenance':context,'science':identity,
        'authorization_sha256':sha(canonical(bundle)),'recipient_sha256':auth['recipient_sha256'],'marker':MARKER,
        'run_seconds':900,'batch_seconds':7200,'attempt':1,'retries':0})

def claim(private):
    identity=freeze();context=hosted_context('confirmation.yml');custody=private/'custody'
    bundle=read(custody/'authority.json');trust=read(custody/'trust.json')
    auth=validate_authority(bundle,trust,context,identity,time.time());protections(auth)
    # Local durable claim-started makes even a lost HTTP response terminal.
    durable(custody/'claim-started.json',{'status':'CLAIM_STARTED_NO_RETRY','provenance':context})
    result=api('POST','/git/refs',{'ref':MARKER,'sha':context['commit']},os.environ['GITHUB_TOKEN'])
    require(result['ref']==MARKER and result['object']['sha']==context['commit'],'MARKER_UNCERTAIN_STOP')
    require(api('GET','/git/ref/'+MARKER[5:])['object']['sha']==context['commit'],'MARKER_VERIFY')
    durable(custody/'claim.json',{'marker':MARKER,'provenance':context})

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=('prepare','claim','seal','audit-authority'));p.add_argument('--private',type=Path,required=True)
    p.add_argument('--trust',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    try:
        if a.phase=='prepare':prepare(a.private.resolve(),a.trust)
        elif a.phase=='claim':claim(a.private.resolve())
        elif a.phase=='audit-authority':
            require(not os.environ.get('GITHUB_ACTIONS'),'OFF_HOST_ONLY')
            custody=a.private;bundle=read(custody/'authority.json');permit=read(custody/'permit.json')
            validate_authority(bundle,read(a.trust),permit['provenance'],freeze(),read(custody/'execution-started.json')['unix'])
        else:
            from crypto import seal
            custody=a.private/'custody';permit=read(custody/'permit.json');trust=read(custody/'trust.json')
            provenance={**permit['provenance'],'science':permit['science'],'recipient_sha256':permit['recipient_sha256'],
                'authorization_sha256':permit['authorization_sha256']}
            seal(custody,a.output,trust['recipient_public_pem'].encode(),provenance)
        print('TRANSPORT_PHASE_FINISHED_NO_PUBLIC_OUTCOMES')
    except BaseException:
        print('TERMINAL_STOP_NO_RETRY');raise SystemExit(1) from None
