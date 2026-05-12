import json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_workload_key = ec.generate_private_key(SECP256R1())

def _pub_jwk(key):
    n = key.public_key().public_numbers()
    def u(v): return base64.urlsafe_b64encode(v.to_bytes(32, 'big')).rstrip(b'=').decode()
    return {'kty': 'EC', 'crv': 'P-256', 'x': u(n.x), 'y': u(n.y)}

_workload_pub_jwk = _pub_jwk(_workload_key)

def get_manifest(origin=""):
    return {
        'workload_pubkey': _workload_pub_jwk,
        'trusted_input_service': {
            'version': 'ztbrowser-trusted-inputs/v1',
            'endpoint_origin': origin,
            'allowed_page_origins': [],
            'profiles': [{
                'profile_id': 'ocr-v1',
                'fields': [{'field_id': 'document', 'kind': 'file', 'required': True, 'label': 'Document'}],
                'submit': {'method': 'POST', 'url': f'{origin}/v1/submit'},
            }],
        }
    }

def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

def decrypt_payload(body):
    epk = body['epk']
    eph_pub = EllipticCurvePublicNumbers(
        int.from_bytes(_b64url_decode(epk['x']), 'big'),
        int.from_bytes(_b64url_decode(epk['y']), 'big'),
        SECP256R1(),
    ).public_key()
    shared = _workload_key.exchange(ECDH(), eph_pub)
    return json.loads(AESGCM(shared).decrypt(
        base64.b64decode(body['iv']),
        base64.b64decode(body['ciphertext']),
        None,
    ))
