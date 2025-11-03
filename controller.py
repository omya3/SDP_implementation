import json
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)
if not os.path.exists('certs'):
    os.makedirs('certs')

USERS_FILE = "users.json"
USERS = {} # username: {spa_key, service_id, cert}

def save_users():
    with open(USERS_FILE, "w") as f:
        # Only serialize standard fields; certs are ASCII PEM so are safe
        json.dump(USERS, f)

def load_users():
    global USERS
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            USERS = json.load(f)

def generate_keys_cert(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f'certs/{username}_private.pem', 'wb') as f: f.write(priv_bytes)
    with open(f'certs/{username}_public.pem', 'wb') as f: f.write(pub_bytes)
    return priv_bytes, pub_bytes

# Load persistent users at boot
load_users()

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    spa_key = secrets.token_bytes(32)
    service_id = secrets.token_bytes(16)
    priv_bytes, pub_bytes = generate_keys_cert(username)
    USERS[username] = {
        'spa_key': spa_key.hex(),
        'service_id': service_id.hex(),
        'cert': pub_bytes.decode()
    }
    save_users()
    print(f'Registered: {username}')
    return jsonify({
        'spa_key': spa_key.hex(),
        'service_id': service_id.hex(),
        'cert': pub_bytes.decode()
    })

@app.route('/api/authorized_spa_keys', methods=['GET'])
def get_authorized_spa_keys():
    return jsonify({user: USERS[user]['spa_key'] for user in USERS})

if __name__ == "__main__":
    app.run(port=8080, debug=True)  # For production, use debug=False
