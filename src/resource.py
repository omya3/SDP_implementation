from flask import Flask, jsonify, make_response, request
import os

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    response = make_response(jsonify({"data": "This is protected data"}))
    response.headers['Connection'] = 'keep-alive'  # Encourages keepalive, but not required for correct proxying
    return response

if __name__ == "__main__":
    # Directory structure for certs
    base_dir = os.path.dirname(os.path.abspath(__file__))
    certs_dir = os.path.join(base_dir, "../certs")
    cert_file = os.path.join(certs_dir, "cert.pem")
    key_file = os.path.join(certs_dir, "key.pem")

    # For local proxy experiments, use plain HTTP (no ssl_context)
    # If you want HTTPS, uncomment the next line and make sure gateway proxy connects using SSL!
    # app.run(host='0.0.0.0', port=8100, ssl_context=(cert_file, key_file))
    app.run(host='0.0.0.0', port=8100)
