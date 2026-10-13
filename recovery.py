"""Versioned recovery bindings; prior seeds remain in protected custody only."""
from transport import *

def protocol():
    p=read(ROOT/'RECOVERY_PROTOCOL.json')
    require(p['operation']==OPERATION and p['science']==read(ROOT/'frozen/identity.json') and
        p['recovery_public_marker']==MARKER and p['recovery_workflow']==WORKFLOW,'RECOVERY_PROTOCOL')
    return p

def binding(seed_manifest_sha256):
    require(isinstance(seed_manifest_sha256,str) and bool(re.fullmatch('[0-9a-f]{64}',seed_manifest_sha256)),'PRIOR_SEED_COMMITMENT')
    require(seed_manifest_sha256==protocol()['prior_seed_manifest_sha256'],'PINNED_PRIOR_SEED_COMMITMENT')
    return {'operation':OPERATION,'protocol_sha256':sha((ROOT/'RECOVERY_PROTOCOL.json').read_bytes()),
        'prior_seed_manifest_sha256':seed_manifest_sha256,'original_run':protocol()['original_run']}

def prior_seeds(raw,expected):
    require(len(raw)<=10000 and sha(raw)==expected,'PRIOR_SEED_MANIFEST_HASH')
    p=protocol();o=p['original_run']
    context={'repository':REPOSITORY,'repository_id':REPOSITORY_ID,'commit':o['commit'],
        'run_id':o['run_id'],'attempt':1,'workflow':'confirmation.yml','manifest_sha256':o['manifest_sha256']}
    permit={'schema':'R18B4_PUBLIC_PERMIT_V1','provenance':context,'science':p['science'],
        'authorization_sha256':o['authorization_sha256'],'recipient_sha256':o['recipient_sha256'],
        'marker':p['original_public_marker'],'run_seconds':900,'batch_seconds':7200,'attempt':1,'retries':0}
    _,_,stats=science_modules()
    return frozenset(stats.validate_seeds(json.loads(raw),sha(canonical(permit))))

def custody_prior(custody):
    b=read(custody/'authority.json')['authorization']['recovery']
    require(b==binding(b['prior_seed_manifest_sha256']),'RECOVERY_BINDING')
    return prior_seeds(regular(custody/'prior-confirmation-seeds.json',10000),b['prior_seed_manifest_sha256'])
