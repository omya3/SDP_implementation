import requests
import urllib3
from flask import Flask, jsonify, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

GATEWAY_URL = "https://localhost:8090"

@app.route("/api/data", methods=["GET"])
def get_data():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "Missing Bearer token", 400
    token = auth.split(" ", 1)[1]
    try:
        resp = requests.post(f"{GATEWAY_URL}/api/check", json={"access_token": token}, timeout=5, verify=False)
        if resp.status_code != 200:
            return "Not authorized", 403
    except requests.RequestException as e:
        print(f"Gateway connection error: {e}")
        return "Gateway unavailable", 503

    # At this point, only legitimate/allowed connections should reach here
    return jsonify({"data": "This is protected resource content."})

if __name__ == "__main__":
    app.run(port=8100, ssl_context=('../cert.pem', '../key.pem'))
