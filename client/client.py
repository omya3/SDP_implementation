import os

import requests
import urllib3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def gen_keys():
    if os.path.exists("user_private.pem") and os.path.exists("user_public.pem"):
        print("Keys already exist, skipping generation.")
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("user_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    public_key = private_key.public_key()
    with open("user_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print("Keys generated.")

def register_key():
    try:
        if not os.path.exists("user_public.pem"):
            print("Public key not found. Generate keys first.")
            return None
        with open("user_public.pem") as f:
            pubkey = f.read()
        resp = requests.post("https://localhost:8080/api/register", json={"username": "alice", "public_key": pubkey}, verify=False)
        print("Register:", resp.status_code, resp.text)
        return resp
    except Exception as e:
        print("Registration error:", e)
        return None

def get_and_sign_challenge(username, private_key_path):
    try:
        r = requests.get(f"https://localhost:8080/api/get_challenge?username={username}", verify=False)
        if r.status_code != 200:
            print("Challenge request failed:", r.status_code, r.text)
            return None, None
        challenge = r.json()["challenge"]
        with open(private_key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        signature = priv.sign(
            challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return challenge, signature
    except Exception as e:
        print("Challenge/sign error:", e)
        return None, None

def send_signed_challenge(username, signature):
    try:
        resp = requests.post(
            "https://localhost:8080/api/authenticate",
            json={"username": username, "signature": signature.hex()}, 
            verify=False
        )
        print("Authenticate:", resp.status_code, resp.text)
        return resp
    except Exception as e:
        print("Authenticate error:", e)
        return None

def access_resource(resource_url, access_token):
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(f"{resource_url}/api/data", headers=headers, verify=False)
        print("Resource access:", resp.status_code, resp.text)
        return resp
    except Exception as e:
        print("Resource access error:", e)
        return None

if __name__ == "__main__":
    gen_keys()
    register_resp = register_key()
    if register_resp is not None and register_resp.status_code in [200, 409]:
        challenge, signature = get_and_sign_challenge("alice", "user_private.pem")
        if challenge and signature:
            resp = send_signed_challenge("alice", signature)
            if resp is not None and resp.status_code == 200:
                token = None
                try:
                    token = resp.json().get("access_token")
                except Exception:
                    print("Failed to parse access token.")
                if token:
                    resource_resp = access_resource("https://localhost:8100", token)
                    if resource_resp is not None:
                        print("Final Resource Response:", resource_resp.status_code, resource_resp.text)
                else:
                    print("No token returned.")
            else:
                print("Authentication failed:", resp.text if resp else "No response")
        else:
            print("Challenge/signing failed.")
    else:
        print("User registration failed or request error.")
