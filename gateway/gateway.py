import requests
import urllib3
from flask import Flask, jsonify, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

CONTROLLER_URL = "https://localhost:8080"

@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json()
    if not data or "access_token" not in data:
        print("Malformed /api/check request")
        return "Missing access_token", 400
    token = data.get("access_token")

    # Always ask controller to verify token validity
    try:
        verify_resp = requests.post(f"{CONTROLLER_URL}/api/verify_token", json={"access_token": token}, timeout=5, verify=False)
        if verify_resp.status_code == 200:
            result = verify_resp.json()
            print(f"Token valid for user: {result.get('username')}")
            return jsonify({"access": "granted"})
        else:
            print(f"Token invalid/expired for /api/check: {token} - {verify_resp.text}")
            return "Not authorized", 403
    except requests.RequestException as e:
        print(f"Controller connection error: {e}")
        return "Controller unavailable", 503


if __name__ == "__main__":
    app.run(port=8090, ssl_context=('../cert.pem', '../key.pem'))
