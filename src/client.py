import hashlib
import hmac
import socket
import ssl
import struct
import sys
import time
import os
import requests
import csv

# --- Directory Structure Awareness ---
base_dir = os.path.dirname(os.path.abspath(__file__))
certs_dir = os.path.join(base_dir, '../certs')
data_dir = os.path.join(base_dir, '../data')

for d in [certs_dir, data_dir]:
    if not os.path.exists(d):
        os.makedirs(d)

CONTROLLER_HOST = 'localhost'
CONTROLLER_PORT = 8080
GATEWAY_HOST = 'localhost'
UDP_PORT = 5005
SPA_ACK_PORT = 6000

def register(username):
    resp = requests.post(
        f'http://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register',
        json={'username': username}).json()
    with open(os.path.join(data_dir, 'spa_key.bin'), 'wb') as f:
        f.write(bytes.fromhex(resp['spa_key']))
    with open(os.path.join(data_dir, 'service_id.bin'), 'wb') as f:
        f.write(bytes.fromhex(resp['service_id']))
    with open(os.path.join(certs_dir, 'client_public.pem'), 'w') as f:
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
    service_id = open(os.path.join(data_dir, 'service_id.bin'), 'rb').read()
    spa_key = open(os.path.join(data_dir, 'spa_key.bin'), 'rb').read()
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
        return None, None
    ack_sock.settimeout(10)
    print(f"[CLIENT] Listening for SPA_ACK on UDP {SPA_ACK_PORT} ...")
    try:
        data, addr = ack_sock.recvfrom(1024)
        msg = data.decode(errors="ignore")
        print(f"[CLIENT] Received {len(data)} bytes from {addr}: {msg}")
        if msg.startswith('SPA_ACCEPTED:'):
            fields = msg.split(':')
            if len(fields) == 3:
                return fields[1], int(fields[2])  # session_id, tls_port
            else:
                return fields[1], None
        else:
            print("[CLIENT] SPA rejected or unknown response")
            return None, None
    except socket.timeout:
        print("[CLIENT] Timeout waiting for SPA_ACK (no packet received).")
        return None, None
    finally:
        ack_sock.close()

def access_service_latency(username):
    SESSION_TIMEOUT = 60  # Sync with gateway setting
    if not wait_until_key_synced(username):
        print("[CLIENT] SPA key not present in gateway – aborting test.")
        return
    send_spa(username)
    session_id, tls_port = wait_for_spa_ack()
    if tls_port is None:
        print("[CLIENT] No port indicated in SPA_ACK. Aborting.")
        return
    print(f"[CLIENT] Session ID received: {session_id}, connecting to port: {tls_port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=os.path.join(certs_dir, "ca_cert.pem"))
    certfile = os.path.join(certs_dir, f"{username}_cert.pem")
    keyfile = os.path.join(certs_dir, f"{username}_private.pem")
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ssl_sock = context.wrap_socket(s, server_hostname=GATEWAY_HOST)
    ssl_sock.connect((GATEWAY_HOST, tls_port))
    req = b"GET /api/data HTTP/1.1\r\nHost: localhost\r\n\r\n"
    print(f"[CLIENT] Sending as many requests as possible during SPA session (timeout {SESSION_TIMEOUT}s)...")
    latencies = []
    count = 0
    with open(os.path.join(data_dir, "latency_samples.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["request_num", "latency_ms"])
        try:
            while True:
                start = time.time()
                ssl_sock.send(req)
                resp = ssl_sock.recv(4096)
                end = time.time()
                ms = (end - start) * 1000
                latencies.append(ms)
                count += 1
                print(f"[CLIENT] Request {count} latency: {ms:.2f} ms")
                writer.writerow([count, ms])
                time.sleep(0.01)
        except Exception as e:
            print("[CLIENT] Connection closed or error after", count, "requests:", e)
    ssl_sock.close()
    if latencies:
        print(f"[CLIENT] Average latency: {sum(latencies)/len(latencies):.2f} ms over {len(latencies)} requests")
        print(f"[CLIENT] All per-request latencies written to latency_samples.csv")

if __name__ == "__main__":
    username = 'aliceIH'
    if len(sys.argv) > 1 and sys.argv[1] == "register":
        register(username)
    else:
        access_service_latency(username)
