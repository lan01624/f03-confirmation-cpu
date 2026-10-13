"""Off-host signatures and custody encryption. Never accepts a private recipient key."""
import base64
import io
import json
from pathlib import Path
import tarfile
import os
from transport import canonical,sha,require,regular,durable,BLOCKS,ARMS

def public_key(pem):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    require(b'PRIVATE KEY' not in pem and pem.startswith(b'-----BEGIN PUBLIC KEY-----'),'PUBLIC_KEY_ONLY')
    return load_pem_public_key(pem)

def fingerprint(key):
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    return sha(key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo))

def signature_verify(payload,signature,pem):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key=public_key(pem);require(isinstance(key,Ed25519PublicKey),'ED25519_SIGNING_KEY_REQUIRED')
    key.verify(base64.b64decode(signature,validate=True),canonical(payload))
    return fingerprint(key)

def recipient(pem,expected):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    key=public_key(pem)
    require(isinstance(key,RSAPublicKey) and key.key_size==3072 and fingerprint(key)==expected,'NEW_RSA3072_RECIPIENT_REQUIRED')
    return key

def seal(custody,destination,pem,provenance):
    from cryptography.hazmat.primitives.asymmetric.padding import OAEP,MGF1
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key=recipient(pem,provenance['recipient_sha256']);buffer=io.BytesIO();total=0;files={}
    require(not custody.is_symlink() and custody.is_dir(),'CUSTODY_DIRECTORY')
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for path in sorted(custody.rglob('*')):
            rel=path.relative_to(custody).parts
            if len(rel)>=3 and rel[0]=='fits' and rel[1] in {b+'-'+a for b in BLOCKS for a in ARMS} and rel[2]=='scratch':continue
            require(not path.is_symlink(),'CUSTODY_SYMLINK')
            if path.is_dir():continue
            raw=regular(path);total+=len(raw);require(total<=200_000_000,'CUSTODY_SIZE')
            name=str(path.relative_to(custody));files[name]=sha(raw)
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.mtime=0
            archive.addfile(info,io.BytesIO(raw))
        raw=canonical({'schema':'R18B4_COMPLETE_CUSTODY_INDEX_V1','files':files})
        info=tarfile.TarInfo('ARCHIVE_INDEX.json');info.size=len(raw);info.mode=0o600
        archive.addfile(info,io.BytesIO(raw))
    secret=AESGCM.generate_key(bit_length=256);nonce=os.urandom(12)
    aad=canonical({'schema':'R18B4_PUBLIC_ENCRYPTED_CUSTODY_V1','provenance':provenance})
    ciphertext=AESGCM(secret).encrypt(nonce,buffer.getvalue(),aad)
    wrapped=key.encrypt(secret,OAEP(mgf=MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    b64=lambda b:base64.b64encode(b).decode('ascii')
    destination.mkdir(mode=0o700,exist_ok=False)
    durable(destination/'encrypted-custody.json',{'schema':'R18B4_AES256GCM_RSA3072OAEP_SHA256_V1',
        'aad':b64(aad),'wrapped_key':b64(wrapped),'nonce':b64(nonce),'ciphertext':b64(ciphertext)})
    durable(destination/'receipt.json',{'schema':'R18B4_PUBLIC_OPAQUE_RECEIPT_V1','status':'ENCRYPTED_REQUIRES_PRIVATE_REVIEW',
        'provenance':provenance,'encrypted_artifact_sha256':sha((destination/'encrypted-custody.json').read_bytes()),
        'lesson_admission':False,'VALIDATED':False})
