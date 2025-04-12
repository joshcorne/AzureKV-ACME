import requests
import time
import json
from config import *
from keyvault import get_or_create_acme_key, get_crypto_client, sign_with_kv
from jwk_utils import jwk_from_kv_key, thumbprint, build_eab
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwk_utils import b64url

class AcmeClient:
    def __init__(self):
        self.kv_key = get_or_create_acme_key()
        self.jwk = jwk_from_kv_key(self.kv_key)
        self.thumbprint = thumbprint(self.jwk)
        self.crypto_client = get_crypto_client(self.kv_key)

        self.session = requests.Session()
        self.dir = self.session.get(ACME_DIRECTORY_URL).json()
        self.nonce = self.session.get(self.dir['newNonce']).headers['Replay-Nonce']
        self.kid = None

    def _post(self, url, payload, use_kid=False):
        protected = {
            "alg": "RS256",
            "nonce": self.nonce,
            "url": url,
        }
        if use_kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk

        jws_obj = sign_with_kv(self.crypto_client, protected, json.dumps(payload).encode())
        response = self.session.post(url, json=jws_obj)
        self.nonce = response.headers.get('Replay-Nonce', self.nonce)
        
        return response

    def register_account(self):
        print("Registering new ACME account...")
        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:" + CONTACT_EMAIL],
            "externalAccountBinding": build_eab(
                self.jwk, 
                EAB_HMAC_KEY, 
                EAB_KID, 
                self.dir['newAccount']
            )
        }
        resp = self._post(self.dir['newAccount'], payload)

        if resp.status_code not in (200, 201):
            raise Exception(f"Registration failed: {resp.status_code} {resp.text}")
        
        self.kid = resp.headers['Location']
        print("ACME Account " + ("already exists." if resp.status_code == 200 else "registered.") + " KID:", self.kid)

        return {
            "status_code": resp.status_code,
            "kid": self.kid,
            "headers": dict(resp.headers)
        }
    
    def create_order(self, domains):
        identifiers = [{"type": "dns", "value": d} for d in domains]
        payload = {"identifiers": identifiers}
        resp = self._post(self.dir['newOrder'], payload, use_kid=True)

        if resp.status_code != 201:
            raise Exception(f"Failed to create order: {resp.status_code} {resp.text}")
        
        return resp.json(), resp.headers['Location']

    def get_challenges(self, order):
        authz_urls = order['authorizations']
        challenges = []

        for url in authz_urls:
            resp = self._post(url, {}, use_kid=True)
            challenges.append(resp.json())

        return challenges
    
    def get_http_challenge_info(self, challenge_obj):
        token = challenge_obj['token']
        key_auth = f"{token}.{self.thumbprint}"
        url = challenge_obj['url']

        return {
            "token": token,
            "key_auth": key_auth,
            "url": url
        }

    def trigger_challenge(self, challenge_url):
        payload = {}  # Empty payload to trigger
        resp = self._post(challenge_url, payload, use_kid=True)

        return resp.status_code in (200, 202)

    def wait_for_valid(self, challenge_url, timeout=120):
        for _ in range(timeout // 2):
            resp = self._post(challenge_url, {}, use_kid=True)
            data = resp.json()

            if data.get("status") == "valid":
                return True
            elif data.get("status") in ("invalid", "failed"):
                raise Exception(f"Challenge failed: {data}")
            
            time.sleep(2)

        raise TimeoutError("Challenge not validated in time")

    def generate_csr(self, domains):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.csr_key = private_key

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
        )
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        csr = csr_builder.sign(private_key, hashes.SHA256())

        return csr.public_bytes(serialization.Encoding.DER)

    def finalize_order(self, order, order_url, domains):
        csr_der = self.generate_csr(domains)
        payload = {"csr": b64url(csr_der)}
        finalize_url = order['finalize']
        resp = self._post(finalize_url, payload, use_kid=True)

        if resp.status_code not in (200, 202):
            raise Exception(f"Order finalization failed: {resp.status_code} {resp.text}")

        # Wait for the order to be valid
        for _ in range(30):
            order_resp = self._post(order_url, {}, use_kid=True)
            order_data = order_resp.json()
            if order_data["status"] == "valid":
                return order_data["certificate"]
            elif order_data["status"] == "invalid":
                raise Exception("Order became invalid")
            time.sleep(2)

        raise TimeoutError("Certificate not ready in time")

    def download_certificate(self, cert_url):
        resp = self._post(cert_url, {}, use_kid=True)

        return resp.content.decode()
