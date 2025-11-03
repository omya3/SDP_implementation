from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    # Print who is hitting the resource for SDP debug purposes
    print("Resource endpoint hit by:", request.remote_addr)
    # Optionally, you could verify a token, source IP (gateway only), etc.
    return jsonify({"data": "This is protected resource content."})

if __name__ == "__main__":
    # NOTE: cert.pem and key.pem must exist (can use self-signed for development)
    app.run(port=8100, ssl_context=('cert.pem', 'key.pem'))
