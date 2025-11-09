# resource.py
from flask import Flask, jsonify, make_response
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [RESOURCE] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint for Kubernetes liveness probe"""
    return jsonify({"status": "ok"}), 200

@app.route("/api/data", methods=["GET"])
def get_data():
    """Protected resource endpoint"""
    logger.debug("GET /api/data called")
    response = make_response(jsonify({"data": "Protected resource accessed!"}))
    response.headers['Connection'] = 'keep-alive'
    return response, 200

if __name__ == "__main__":
    logger.info("Starting Resource Server on HTTP port 8100")
    app.run(host='0.0.0.0', port=8100, debug=False)
