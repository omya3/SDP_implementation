import subprocess
import threading

import requests
import urllib3
from flask import Flask, jsonify, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

CONTROLLER_URL = "https://localhost:8080"



def open_temporary_port(client_ip, port=8100, timeout=30):
    subprocess.run([
        "iptables", "-I", "INPUT", "1",
        "-p", "tcp", "--dport", str(port), "-s", client_ip, "-j", "ACCEPT"
    ], check=True)
    def remove_rule():
        subprocess.run([
            "iptables", "-D", "INPUT",
            "-p", "tcp", "--dport", str(port), "-s", client_ip, "-j", "ACCEPT"
        ], check=True)
    threading.Timer(timeout, remove_rule).start()

@app.route("/api/sdp_access", methods=["POST"])
def sdp_access():
    data = request.get_json()
    if not data or "access_token" not in data:
        return "Missing access_token", 400
    token = data.get("access_token")
    # Verify token with controller, as in /api/check
    verify_resp = requests.post(f"{CONTROLLER_URL}/api/verify_token",
                               json={"access_token": token}, timeout=5, verify=False)
    if verify_resp.status_code != 200:
        return "Not authorized", 403

    client_ip = request.remote_addr
    open_temporary_port(client_ip, port=8100, timeout=30)
    print(f"Firewall opened for {client_ip} port 8100")
    return jsonify({"access": "granted"})



if __name__ == "__main__":
    app.run(port=8090, ssl_context=('../cert.pem', '../key.pem'))
