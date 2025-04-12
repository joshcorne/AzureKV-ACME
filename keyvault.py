from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from azure.core.exceptions import ResourceNotFoundError
import json, hashlib
from jwk_utils import b64url

from config import VAULT_URL, EAB_KID, CREATED_KEY_SIZE

credential = DefaultAzureCredential()

def get_or_create_acme_key():
    key_client = KeyClient(VAULT_URL, credential)
    try:
        return key_client.get_key(EAB_KID)
    except ResourceNotFoundError:
        return key_client.create_rsa_key(
            name=EAB_KID,
            size=CREATED_KEY_SIZE
        )

def get_crypto_client(kv_key):
    return CryptographyClient(kv_key.id, credential)

def sign_with_kv(crypto_client, protected, payload):
    protected_b64 = b64url(json.dumps(protected).encode())
    payload_b64 = b64url(payload)
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    digest = hashlib.sha256(signing_input).digest()
    signed = crypto_client.sign(SignatureAlgorithm.rs256, digest)
    signature_b64 = b64url(signed.signature)

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    }
