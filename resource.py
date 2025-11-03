from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    response = make_response(jsonify({"data": "This is protected data"}))
    response.headers['Connection'] = 'keep-alive'  # Encourages keepalive, but not required for correct proxying
    return response

if __name__ == "__main__":
    # For local proxy experiments, use plain HTTP (no ssl_context)
    # If you want HTTPS, uncomment and make sure your gateway proxy also connects using SSL!
    # app.run(host='0.0.0.0', port=8100, ssl_context=('cert.pem', 'key.pem'))
    app.run(host='0.0.0.0', port=8100)
