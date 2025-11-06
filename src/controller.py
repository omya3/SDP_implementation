import json
import os
import secrets
import logging
from flask import Flask, jsonify, request

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [CONTROLLER] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

configs_dir = "/app/configs"
if not os.path.exists(configs_dir):
    os.makedirs(configs_dir)

USERS_FILE = os.path.join(configs_dir, "users.json")
USERS = {}

def save_users():
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(USERS, f)
    except Exception as e:
        logger.error(f"Failed to save users: {e}")

def load_users():
    global USERS
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                USERS = json.load(f)
                logger.info(f"Loaded {len(USERS)} users from {USERS_FILE}")
        else:
            USERS = {}
            logger.info("No existing users file found")
    except Exception as e:
        logger.error(f"Failed to load users: {e}")
        USERS = {}

load_users()
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Kubernetes liveness probe"""
    return jsonify({"status": "ok"}), 200

@app.route('/register', methods=['POST'])
def register():
    """Register a new user and generate SPA credentials"""
    try:
        username = request.json['username']
        spa_key = secrets.token_bytes(32)
        service_id = secrets.token_bytes(16)
        user_cert = "STUB_CERT_" + username

        USERS[username] = {
            'spa_key': spa_key.hex(),
            'service_id': service_id.hex(),
            'cert': user_cert
        }
        save_users()
        logger.info(f'Registered user: {username}')
        
        return jsonify({
            'spa_key': spa_key.hex(),
            'service_id': service_id.hex(),
            'cert': user_cert
        }), 200
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/authorized_spa_keys', methods=['GET'])
def get_authorized_spa_keys():
    """Fetch all authorized SPA keys for gateway"""
    try:
        return jsonify({user: USERS[user]['spa_key'] for user in USERS}), 200
    except Exception as e:
        logger.error(f"Failed to fetch SPA keys: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info("Starting Controller on HTTPS (adhoc self-signed cert, unverified)")
    app.run(host="0.0.0.0", port=8080, debug=False, ssl_context='adhoc')
