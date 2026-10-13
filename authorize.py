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
from recovery import binding,protocol,prior_seeds,custody_prior

ENVIRONMENT='r18b4-independent-evaluator'

def validate_authority(bundle,trust,context,identity,now):
    require(set(bundle)=={'authorization','pi_signature','evaluator_signature','reservation','reservation_pi_signature'},'AUTHORIZATION_SCHEMA')
    auth=bundle['authorization'];reservation=bundle['reservation']
    expected={'schema','provenance','science','evaluator_login','evaluator_id','owner_login','recipient_sha256',
        'reservation_sha256','expires_unix','approval_digest','accepts_n3_limit','off_host_owner_key_attestation','transport_amendment_approved',
        'operation','owner_id','human_review','independent_human_review','recovery'}
    require(set(auth)==expected,'AUTHORIZATION_FIELDS')
    require(auth['schema']=='R18B4_RECOVERY_AUTHORIZATION_V1' and auth['operation']==OPERATION and
        auth['provenance']==context and auth['science']==identity,'SIGNED_RUN_SCIENCE_BINDING')
    require(auth['owner_login']==auth['evaluator_login']==trust['evaluator_login']==OWNER_LOGIN,'SOLE_OWNER_REQUIRED')
    require(type(auth['owner_id']) is int and type(auth['evaluator_id']) is int and type(trust['evaluator_id']) is int and
        auth['owner_id']==auth['evaluator_id']==trust['evaluator_id']==OWNER_ID,'OWNER_ACCOUNT_IDENTITY')
    require(auth['human_review']=='OWNER_OPERATED' and auth['independent_human_review'] is False,'SINGLE_OPERATOR_DISCLOSURE')
    require(type(auth['expires_unix']) is int and now<auth['expires_unix']<=now+86400,'AUTHORIZATION_EXPIRY')
    require(auth['accepts_n3_limit'] is True and auth['off_host_owner_key_attestation'] is True and auth['transport_amendment_approved'] is True,'SUBSTANTIVE_APPROVAL')
    pi=signature_verify(auth,bundle['pi_signature'],trust['pi_signing_public_pem'].encode())
    evaluator=signature_verify(auth,bundle['evaluator_signature'],trust['evaluator_signing_public_pem'].encode())
    require(pi!=evaluator and pi==trust['pi_signing_sha256'] and evaluator==trust['evaluator_signing_sha256'],'DISTINCT_SIGNERS')
    require(auth['recipient_sha256']==trust['recipient_sha256'],'EVALUATOR_RECIPIENT')
    recipient(trust['recipient_public_pem'].encode(),auth['recipient_sha256'])
    require(auth['reservation_sha256']==sha(canonical(reservation)),'RESERVATION_BINDING')
    signature_verify(reservation,bundle['reservation_pi_signature'],trust['pi_signing_public_pem'].encode())
    require(set(reservation)=={'schema','science','public_repository_id','public_commit','old_marker','old_marker_commit','private_delegation_commit','status','recovery'},'RESERVATION_FIELDS')
    require(reservation['schema']=='R18B4_RECOVERY_RESERVATION_V1' and reservation['status']=='RECOVERY_ROUTE_RESERVED_NO_FITS' and
        reservation['science']==identity and reservation['public_repository_id']==REPOSITORY_ID and
        reservation['public_commit']==context['commit'] and reservation['old_marker']==protocol()['recovery_private_marker'],'PRIVATE_ROUTE_NOT_RESERVED')
    for k in ('old_marker_commit','private_delegation_commit'):
        require(bool(re.fullmatch('[0-9a-f]{40}',reservation[k])),'PRIVATE_RESERVATION_COMMIT')
    require(bool(re.fullmatch('[0-9a-f]{64}',auth['approval_digest'])),'REVIEWER_DIGEST')
    require(auth['provenance']['workflow']==WORKFLOW and auth['recovery']==reservation['recovery']==binding(auth['recovery']['prior_seed_manifest_sha256']),'RECOVERY_AUTHORITY_BINDING')
    return auth

def api(method,path,body=None,token=None):
    # Private repository endpoints cannot be expressed. Token only for this marker.
    allowed_reads={'','/git/ref/heads/main','/branches/main','/environments/'+ENVIRONMENT,
        '/environments/'+ENVIRONMENT+'/deployment-branch-policies','/git/ref/'+MARKER[5:],
        '/git/ref/'+protocol()['original_public_marker'][5:]}
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
    branch=api('GET','/branches/main')
    require(branch['protected'] is True and branch['commit']['sha']==auth['provenance']['commit'],'PROTECTED_MAIN_REQUIRED')
    checks=branch['protection']['required_status_checks']
    require(checks['enforcement_level']=='everyone' and {'context':'owner-transport-checks','app_id':15368} in checks['checks'],'OWNER_TRANSPORT_CHECK_REQUIRED')
    env=api('GET','/environments/'+ENVIRONMENT)
    require(env.get('can_admins_bypass') is False,'ADMIN_BYPASS_MUST_BE_DISABLED')
    rule=next((r for r in env['protection_rules'] if r['type']=='required_reviewers'),None)
    require(rule is not None and rule.get('prevent_self_review') is False,'OWNER_SELF_REVIEW_MUST_BE_ALLOWED')
    reviewers=rule['reviewers']
    require(len(reviewers)==1 and reviewers[0]['type']=='User' and
        reviewers[0]['reviewer']['id']==auth['evaluator_id']==OWNER_ID and
        reviewers[0]['reviewer']['login']==auth['evaluator_login']==OWNER_LOGIN,'OWNER_ONLY_REVIEWER')
    require(env['deployment_branch_policy']=={'protected_branches':False,'custom_branch_policies':True},'MAIN_ONLY_DEPLOYMENT_POLICY')
    policy=api('GET','/environments/'+ENVIRONMENT+'/deployment-branch-policies')['branch_policies']
    require(len(policy)==1 and policy[0]['name']=='main' and policy[0]['type']=='branch','MAIN_ONLY_ENVIRONMENT')
    return {'environment':env,'branch_policies':policy,'branch':branch}

def prepare(private,trust_path):
    identity=freeze();context=hosted_context(WORKFLOW);activation=read(ROOT/'activation.json')
    require(activation['schema']=='R18B4_PUBLIC_ACTIVATION_V2' and activation['operation']==OPERATION and
        activation['real_execution_authorized'] is True and activation['status']=='PROSPECTIVELY_APPROVED','PRODUCTION_DISABLED')
    require(os.environ.get('GITHUB_ACTOR')==OWNER_LOGIN and os.environ.get('GITHUB_TRIGGERING_ACTOR')==OWNER_LOGIN and
        os.environ.get('GITHUB_ACTOR_ID')==str(OWNER_ID),'OWNER_DISPATCH_REQUIRED')
    trust=read(trust_path);bundle=json.loads(os.environ['R18B4_SIGNED_AUTHORIZATION'])
    auth=validate_authority(bundle,trust,context,identity,time.time())
    import hmac
    require(hmac.compare_digest(auth['approval_digest'],os.environ.get('R18B4_REVIEWER_APPROVAL_SHA256','')),'OWNER_REVIEW_DIGEST')
    require(not private.exists() and not private.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(private.resolve()),'FRESH_EXTERNAL_CUSTODY')
    proof=protections(auth)
    prior_raw=os.environ['R18B4_PRIOR_SEED_MANIFEST'].encode()
    prior_seeds(prior_raw,auth['recovery']['prior_seed_manifest_sha256'])
    require(api('GET','/git/ref/'+protocol()['original_public_marker'][5:])['object']['sha']==protocol()['original_run']['commit'],'ORIGINAL_MARKER_PRESERVED')
    private.mkdir(mode=0o700);custody=private/'custody';custody.mkdir(mode=0o700)
    with (custody/'prior-confirmation-seeds.json').open('xb') as f:f.write(prior_raw);f.flush();os.fsync(f.fileno())
    durable(custody/'authority.json',bundle);durable(custody/'trust.json',trust);durable(custody/'protections.json',proof)
    durable(custody/'permit.json',{'schema':'R18B4_PUBLIC_PERMIT_V1','provenance':context,'science':identity,
        'authorization_sha256':sha(canonical(bundle)),'recipient_sha256':auth['recipient_sha256'],'marker':MARKER,
        'run_seconds':900,'batch_seconds':7200,'attempt':1,'retries':0})

def claim(private):
    identity=freeze();context=hosted_context(WORKFLOW);custody=private/'custody'
    bundle=read(custody/'authority.json');trust=read(custody/'trust.json')
    auth=validate_authority(bundle,trust,context,identity,time.time());protections(auth)
    custody_prior(custody)
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
