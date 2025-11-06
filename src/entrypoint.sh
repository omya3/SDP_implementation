#!/bin/bash
set -e
POD_IP=$(hostname -i | awk '{print $1}')
echo "[ENTRYPOINT] POD_IP: $POD_IP"
python3 /app/generate_cert.py "$POD_IP"
exec python3 /app/gateway.py
