import os
import socket
import subprocess
import sys

CERTS_DIR = "/app/certs"
os.makedirs(CERTS_DIR, exist_ok=True)

def get_pod_ip():
    return socket.gethostbyname(socket.gethostname())

def make_cert_files(certfile, keyfile, cafile, pod_ip):
    subj = "/CN=sdp-gateway"
    openssl_config = f"""
[req]
distinguished_name = req
x509_extensions = v3_req
prompt = no

[v3_req]
subjectAltName = DNS:sdp-gateway,IP:{pod_ip}
"""
    config_path = os.path.join(CERTS_DIR, "openssl_san.cnf")
    with open(config_path, "w") as f:
        f.write(openssl_config)

    subprocess.check_call([
        "openssl", "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", keyfile,
        "-out", certfile,
        "-subj", subj,
        "-config", config_path,
        "-extensions", "v3_req"
    ])
    subprocess.check_call([
        "cp", certfile, cafile
    ])

if __name__ == "__main__":
    pod_ip = sys.argv[1] if len(sys.argv) > 1 else get_pod_ip()
    certfile = os.path.join(CERTS_DIR, "gateway_cert.pem")
    keyfile = os.path.join(CERTS_DIR, "gateway_key.pem")
    cafile = os.path.join(CERTS_DIR, "ca_cert.pem")
    make_cert_files(certfile, keyfile, cafile, pod_ip)

