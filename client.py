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
    resp = requests.post(
        f'http://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register',
        json={'username': username}).json()
    if not os.path.exists('certs'):
        os.makedirs('certs')
    with open('spa_key.bin', 'wb') as f:
        f.write(bytes.fromhex(resp['spa_key']))
    with open('service_id.bin', 'wb') as f:
        f.write(bytes.fromhex(resp['service_id']))
    with open('certs/client_public.pem', 'w') as f:
        f.write(resp['cert'])
    print("[CLIENT] Registered and saved keys/certs for username:", username)
    print("[CLIENT] SPA Key (hex):", resp['spa_key'])
    print("[CLIENT] Service ID (hex):", resp['service_id'])

def wait_until_key_synced(username, timeout=20):
    print(f"[CLIENT] Waiting for gateway/SPA key sync for username: {username}...")
    for i in range(timeout):
        try:
            resp = requests.get(f'http://{CONTROLLER_HOST}:{CONTROLLER_PORT}/api/authorized_spa_keys', timeout=2)
            users = resp.json()
            if username in users:
                print(f"[CLIENT] Username {username} is now authorized in gateway.")
                return True
            else:
                print(f"[CLIENT] Not yet authorized ({i}) ... retrying ...")
        except Exception as e:
            print("[CLIENT] Key sync check error:", e)
        time.sleep(1)
    print(f"[CLIENT] SPA key for {username} never appeared in authorized list (timeout)!")
    return False

def send_spa(username):
    client_id = username.encode()
    nonce = os.urandom(8)
    timestamp = int(time.time())
    service_id = open('service_id.bin', 'rb').read()
    spa_key = open('spa_key.bin', 'rb').read()
    msg = client_id + nonce + struct.pack(">I", timestamp) + service_id
    hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest()
    packet = msg + hmac_val
    print("\n[CLIENT] --- SENDING SPA PACKET ---")
    print(f"[CLIENT] username: {username}")
    print(f"[CLIENT] client_id (hex): {client_id.hex()} (len={len(client_id)})")
    print(f"[CLIENT] nonce (hex): {nonce.hex()}")
    print(f"[CLIENT] timestamp: {timestamp}")
    print(f"[CLIENT] service_id (hex): {service_id.hex()}")
    print(f"[CLIENT] Full msg (hex): {msg.hex()}")
    print(f"[CLIENT] spa_key (hex): {spa_key.hex()}")
    print(f"[CLIENT] hmac_val (hex): {hmac_val.hex()}")
    print(f"[CLIENT] full packet (hex): {packet.hex()}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (GATEWAY_HOST, UDP_PORT))
    print(f"[CLIENT] Sent SPA packet to {GATEWAY_HOST}:{UDP_PORT}")

def wait_for_spa_ack():
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ack_sock.bind(('0.0.0.0', SPA_ACK_PORT))
    except Exception as e:
        print(f"[CLIENT] Failed to bind UDP port {SPA_ACK_PORT} for ACK:", e)
        return None
    ack_sock.settimeout(10)
    print(f"[CLIENT] Listening for SPA_ACK on UDP {SPA_ACK_PORT} ...")
    try:
        data, addr = ack_sock.recvfrom(1024)
        msg = data.decode(errors="ignore")
        print(f"[CLIENT] Received {len(data)} bytes from {addr}: {msg}")
        if msg.startswith('SPA_ACCEPTED:'):
            return msg.split(':', 1)[1]
        else:
            print("[CLIENT] SPA rejected or unknown response")
            return None
    except socket.timeout:
        print("[CLIENT] Timeout waiting for SPA_ACK (no packet received).")
        return None
    finally:
        ack_sock.close()

def access_service_latency(username):
    if not wait_until_key_synced(username):
        print("[CLIENT] SPA key not present in gateway – aborting test.")
        return
    send_spa(username)
    session_id = wait_for_spa_ack()
    print(f"[CLIENT] Session ID received: {session_id}")
    if session_id:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(s)
        ssl_sock.connect((GATEWAY_HOST, TLS_PORT))
        req = b"GET /api/data HTTP/1.1\r\nHost: localhost\r\n\r\n"
        print("[CLIENT] Sending HTTP GET /api/data to gateway proxy...")
        start = time.time()
        ssl_sock.send(req)
        resp = ssl_sock.recv(1024)
        end = time.time()
        ssl_sock.close()
        print("[CLIENT] Service response:")
        print(resp.decode(errors="ignore"))
        print(f"[CLIENT] SDP Service Access Latency: {end-start:.3f} seconds")

if __name__ == "__main__":
    username = 'aliceIH'
    if len(sys.argv) > 1 and sys.argv[1] == "register":
        register(username)
    else:
        access_service_latency(username)
