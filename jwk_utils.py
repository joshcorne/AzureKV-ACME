import json
import base64
import hashlib
import hmac

def b64url(data) -> str:
    if isinstance(data, int):
        # Convert int to bytes (big-endian)
        byte_length = (data.bit_length() + 7) // 8
        data = data.to_bytes(byte_length, 'big')

    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def jwk_from_kv_key(kv_key):
    key = kv_key.key
    return {
        "kty": key.kty,
        "n": b64url(key.n),
        "e": b64url(key.e),
    }


def thumbprint(jwk_dict):
    json_str = json.dumps({
        "e": jwk_dict["e"],
        "kty": jwk_dict["kty"],
        "n": jwk_dict["n"]
    }, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(json_str.encode()).digest()
    return b64url(digest)

def build_eab(jwk_dict, eab_hmac_key, eab_kid, acme_url):
    # Protected header for the EAB (symmetric key binding)
    protected = {
        "alg": "HS256",
        "kid": eab_kid,
        "url": acme_url
    }
    protected_b64 = b64url(json.dumps(protected, separators=(',', ':')).encode())
    payload_b64 = b64url(json.dumps(jwk_dict, separators=(',', ':')).encode())
    signing_input = f"{protected_b64}.{payload_b64}".encode()

    # Decode base64url HMAC key (add padding if needed)
    padded_key = eab_hmac_key + '=' * (-len(eab_hmac_key) % 4)
    hmac_key = base64.urlsafe_b64decode(padded_key)

    # Sign the payload using HMAC-SHA256
    signature = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()
    signature_b64 = b64url(signature)

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    }