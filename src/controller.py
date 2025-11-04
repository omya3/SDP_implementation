import json
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

# --- Directory Structure Awareness ---
base_dir = os.path.dirname(os.path.abspath(__file__))
certs_dir = os.path.join(base_dir, '../certs')
configs_dir = os.path.join(base_dir, '../configs')

for d in [certs_dir, configs_dir]:
    if not os.path.exists(d):
        os.makedirs(d)

USERS_FILE = os.path.join(configs_dir, "users.json")
USERS = {} # username: {spa_key, service_id, cert}

def save_users():
    with open(USERS_FILE, "w") as f:
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
    with open(os.path.join(certs_dir, f'{username}_private.pem'), 'wb') as f:
        f.write(priv_bytes)
    with open(os.path.join(certs_dir, f'{username}_public.pem'), 'wb') as f:
        f.write(pub_bytes)
    return priv_bytes, pub_bytes

# Load persistent users at boot
load_users()

app = Flask(__name__)

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
