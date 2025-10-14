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
    # Optionally, verify with gateway or just serve content.
    return jsonify({"data": "This is protected resource content."})


if __name__ == "__main__":
    app.run(port=8100, ssl_context=('../cert.pem', '../key.pem'))
