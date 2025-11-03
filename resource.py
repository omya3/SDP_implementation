from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    response = make_response(jsonify({"data": "This is protected data"}))
    response.headers['Connection'] = 'keep-alive'
    return response

if __name__ == "__main__":
    # Note the ssl_context parameter!
    app.run(host='0.0.0.0', port=8100, ssl_context=('cert.pem', 'key.pem'))
