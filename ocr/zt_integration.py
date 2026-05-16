import base64
import json
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_workload_key = ec.generate_private_key(SECP256R1())


def _pub_jwk(key):
    numbers = key.public_key().public_numbers()

    def encode(value):
        return (
            base64.urlsafe_b64encode(value.to_bytes(32, "big"))
            .rstrip(b"=")
            .decode()
        )

    return {"kty": "EC", "crv": "P-256", "x": encode(numbers.x), "y": encode(numbers.y)}


_workload_pub_jwk = _pub_jwk(_workload_key)


def _origin_with_host(scheme, host, port=None):
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port is None or default_port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def canonical_origin(origin=""):
    if not origin:
        return ""
    parsed = urlsplit(origin)
    if not parsed.scheme or not parsed.hostname:
        return origin.rstrip("/")
    return _origin_with_host(parsed.scheme, parsed.hostname, parsed.port)


def allowed_page_origins(origin):
    canonical = canonical_origin(origin)
    if not canonical:
        return []

    parsed = urlsplit(canonical)
    origins = [canonical]
    for host in ("localhost", "127.0.0.1"):
        origins.append(_origin_with_host(parsed.scheme, host, parsed.port))
    return list(dict.fromkeys(origins))


def landing_manifest(origin):
    canonical = canonical_origin(origin)
    attestation_url = f"{canonical}/.well-known/attestation" if canonical else "/.well-known/attestation"
    return {
        "version": "ztbrowser-trusted-inputs/v1",
        "endpoint_refs": [
            {
                "endpoint_ref": "ocr",
                "origin": canonical,
                "attestation_url": attestation_url,
            }
        ],
        "groups": [{"group_id": "ocr", "endpoint_ref": "ocr", "profile_id": "ocr-v1"}],
    }


def landing_manifest_json(origin):
    return json.dumps(landing_manifest(origin), indent=2)


def get_manifest(origin=""):
    canonical = canonical_origin(origin)
    submit_url = f"{canonical}/v1/submit" if canonical else "/v1/submit"
    return {
        "workload_pubkey": _workload_pub_jwk,
        "trusted_input_service": {
            "version": "ztbrowser-trusted-inputs/v1",
            "endpoint_origin": canonical,
            "allowed_page_origins": allowed_page_origins(canonical),
            "profiles": [
                {
                    "profile_id": "ocr-v1",
                    "fields": [
                        {
                            "field_id": "document",
                            "kind": "file",
                            "required": True,
                            "label": "Document",
                        }
                    ],
                    "submit": {"method": "POST", "url": submit_url},
                }
            ],
        },
    }


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (4 - len(value) % 4))


def decrypt_payload(body):
    epk = body["epk"]
    eph_pub = EllipticCurvePublicNumbers(
        int.from_bytes(_b64url_decode(epk["x"]), "big"),
        int.from_bytes(_b64url_decode(epk["y"]), "big"),
        SECP256R1(),
    ).public_key()
    shared = _workload_key.exchange(ECDH(), eph_pub)
    return json.loads(
        AESGCM(shared).decrypt(
            base64.b64decode(body["iv"]),
            base64.b64decode(body["ciphertext"]),
            None,
        )
    )
