import hashlib
import hmac
import socket
import ssl
import struct
import sys
import time
import os

import requests

CONTROLLER_HOST = 'localhost'
CONTROLLER_PORT = 8080
GATEWAY_HOST = 'localhost'
UDP_PORT = 5005
TLS_PORT = 5006
SPA_ACK_PORT = 6000

def register(username):
    resp = requests.post(f'http://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register', json={'username': username}).json()
    with open('spa_key.bin', 'wb') as f:
        f.write(bytes.fromhex(resp['spa_key']))
    with open('service_id.bin', 'wb') as f:
        f.write(bytes.fromhex(resp['service_id']))
    with open('certs/client_public.pem', 'w') as f:
        f.write(resp['cert'])
    print("Client: Registered and saved keys/certs")

def send_spa(username):
    client_id = username[:8].encode().ljust(8, b'\0')
    nonce = os.urandom(8)
    timestamp = int(time.time())
    service_id = open('service_id.bin', 'rb').read()
    spa_key = open('spa_key.bin', 'rb').read()
    msg = client_id + nonce + struct.pack(">I", timestamp) + service_id
    hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest()
    packet = msg + hmac_val
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (GATEWAY_HOST, UDP_PORT))
    print("Client: Sent SPA packet")

def wait_for_spa_ack():
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ack_sock.bind(('0.0.0.0', SPA_ACK_PORT))
    ack_sock.settimeout(10)
    try:
        data, _ = ack_sock.recvfrom(1024)
        msg = data.decode()
        if msg.startswith('SPA_ACCEPTED:'):
            return msg.split(':', 1)[1]
        else:
            print("Client: SPA rejected or unknown response")
            return None
    except socket.timeout:
        print("Client: Timeout waiting for SPA_ACK")
        return None

def access_service_latency(username):
    send_spa(username)
    session_id = wait_for_spa_ack()
    print("Session ID received:", session_id)
    if session_id:
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(s)
        ssl_sock.connect((GATEWAY_HOST, TLS_PORT))
        ssl_sock.send(b'GET /service')
        resp = ssl_sock.recv(1024)
        end = time.time()
        ssl_sock.close()
        print("Service response:", resp)
        print(f"SDP Service Access Latency: {end-start:.3f} seconds")

if __name__ == "__main__":
    username = 'aliceIH'
    if len(sys.argv) > 1 and sys.argv[1] == "register":
        register(username)
    else:
        access_service_latency(username)
