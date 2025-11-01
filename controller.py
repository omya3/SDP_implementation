import secrets
import time

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, jsonify, request

app = Flask(__name__)
users = {}          # username: public_key (PEM string)
challenges = {}     # username: challenge
active_tokens = {}  # token: {username, expires}

def generate_challenge():
    return secrets.token_hex(16)

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            print("Malformed register request: no JSON")
            return "Malformed request", 400
        username = data.get('username')
        public_key = data.get('public_key')
        if not username or not public_key:
            print("Malformed register request: missing username or public_key")
            return "Missing username or public_key", 400
        if username in users:
            print(f"Register attempt for existing user: {username}")
            return "User already registered", 409
        users[username] = public_key
        print(f"Registered: {username}")
        return "User registered", 200
    except Exception as e:
        print(f"Register error: {e}")
        return "Internal server error", 500

@app.route('/api/get_challenge')
def get_challenge():
    try:
        username = request.args.get('username')
        if not username or username not in users:
            print("Malformed or unknown user for challenge")
            return "Unknown user", 403
        challenge = generate_challenge()
        challenges[username] = challenge
        print(f"Challenge issued for user: {username}")
        return jsonify({"challenge": challenge})
    except Exception as e:
        print(f"Get challenge error: {e}")
        return "Internal server error", 500

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    try:
        data = request.get_json()
        if not data:
            print("Malformed authenticate request: no JSON")
            return "Malformed request", 400
        username = data.get('username')
        signature_hex = data.get('signature')
        if not username or not signature_hex:
            print("Malformed authenticate request: missing fields")
            return "Missing fields", 400
        signature = bytes.fromhex(signature_hex)
        if username not in users or username not in challenges:
            print("Unknown user or no challenge")
            return "Unknown user or no challenge", 403
        challenge = challenges[username]
        public_key_pem = users[username]
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        try:
            public_key.verify(
                signature,
                challenge.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print(f"Signature verification failed for {username}: {e}")
            return "Signature verification failed", 401
        # If verification succeeds, delete challenge and issue token
        del challenges[username]
        token = secrets.token_hex(16)
        active_tokens[token] = {"username": username, "expires": time.time() + 4}
        print(f"Authenticated: {username}, token: {token}")
        return jsonify({"access_token": token})
    except Exception as e:
        print(f"Authenticate error: {e}")
        return "Internal server error", 500

@app.route('/api/verify_token', methods=['POST'])
def verify_token():
    try:
        data = request.get_json()
        if not data:
            print("Malformed verify_token request: no JSON")
            return "Malformed request", 400
        token = data.get("access_token")
        if not token:
            print("Malformed verify_token request: missing access_token")
            return "Missing access_token", 400
        info = active_tokens.get(token)
        if not info:
            print(f"Invalid token verification attempt for token: {token}")
            return "Invalid token", 403
        if info["expires"] < time.time():
            print(f"Expired token verification attempt for token: {token}")
            return "Token expired", 403
        return jsonify({"valid": True, "username": info["username"]})
    except Exception as e:
        print(f"Verify token error: {e}")
        return "Internal server error", 500


if __name__ == "__main__":
    app.run(port=8080, ssl_context=('cert.pem', 'key.pem'))

