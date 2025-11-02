import json
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)
if not os.path.exists('certs'):
    os.makedirs('certs')
USERS = {} # username: {spa_key, service_id, cert}

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
    print(f'Registered: {username}')
    return jsonify({
        'spa_key': spa_key.hex(),
        'service_id': service_id.hex(),
        'cert': pub_bytes.decode()
    })

@app.route('/api/authorized_spa_keys', methods=['GET'])
def get_authorized_spa_keys():
    # Provide all authorized IH SPA keys (can add access checks in real deployment)
    # Returns: {username: spa_key, ...}
    return jsonify({user: USERS[user]['spa_key'] for user in USERS})

if __name__ == "__main__":
    app.run(port=8080, debug=True)
