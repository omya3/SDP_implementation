import hashlib
import hmac
import secrets
import socket
import ssl
import struct
import subprocess  # For firewall rule changes
import threading
import time

import requests

SERVER_HOST = '0.0.0.0'
UDP_PORT = 5005
SPA_ACK_PORT = 6000
TLS_PORT = 5006
SESSION_TIMEOUT = 20
CONTROLLER_URL = 'http://localhost:8080'

AUTHORIZED_SPAS = {}  # username: spa_key

def open_firewall_port(client_ip, port):
    # Allow client_ip access to port for TCP inbound
    cmd = [
        "sudo", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port),
        "-s", client_ip, "-j", "ACCEPT"
    ]
    print("Opening firewall port for", client_ip)
    subprocess.run(cmd, check=True)

def close_firewall_port(client_ip, port):
    # Remove specific firewall rule for client_ip and port
    cmd = [
        "sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
        "-s", client_ip, "-j", "ACCEPT"
    ]
    print("Closing firewall port for", client_ip)
    subprocess.run(cmd, check=True)


def fetch_authorized_spa_keys():
    global AUTHORIZED_SPAS
    try:
        resp = requests.get(f"{CONTROLLER_URL}/api/authorized_spa_keys", timeout=3)
        AUTHORIZED_SPAS = {user: bytes.fromhex(spa) for user, spa in resp.json().items()}
        print(f"Fetched authorized SPA keys: {list(AUTHORIZED_SPAS.keys())}")
    except Exception as e:
        print("ERROR: Could not fetch SPA keys:", e)

def periodic_refresh():
    while True:
        fetch_authorized_spa_keys()
        time.sleep(30)

def start_tls_session(session_id, valid_until):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((SERVER_HOST, TLS_PORT))
    server_sock.listen(1)
    print(f"mTLS service listening for session {session_id}")
    while True:
        client_sock, addr = server_sock.accept()
        start_time = time.time()
        ssl_sock = ssl.wrap_socket(client_sock, server_side=True, certfile="certs/aliceIH_public.pem", keyfile="certs/aliceIH_private.pem")
        print("Accepted mTLS connection from", addr)
        while time.time() < valid_until:
            try:
                req = ssl_sock.recv(1024)
                if not req:
                    break
                ssl_sock.send(b"Service response OK\n")
            except Exception as e:
                break
        # Session expired
        print("Session expired or closed for", addr)
        ssl_sock.close()
        break
    server_sock.close()

def spa_listener():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SERVER_HOST, UDP_PORT))
    print('AH: Listening for SPA...')
    while True:
        data, addr = udp_sock.recvfrom(4096)
        client_ip, _ = addr
        try:
            client_id = data[:8].decode(errors='ignore').strip('\0')
            nonce = data[8:16]
            timestamp = struct.unpack(">I", data[16:20])[0]
            service_id = data[20:36]
            hmac_recv = data[36:]
            spa_key = AUTHORIZED_SPAS.get(client_id)
            msg = data[:36]
            hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest() if spa_key else None
            now = time.time()
            if hmac_val == hmac_recv and abs(now - timestamp) < SESSION_TIMEOUT:
                session_id = secrets.token_hex(8)
                valid_until = now + SESSION_TIMEOUT
                print(f"Valid SPA from {client_ip} ({client_id}), session {session_id}")
                # --- NEW: Open the firewall for this session ---
                open_firewall_port(client_ip, TLS_PORT)
                # Start mTLS service with session lifetime
                threading.Thread(target=start_tls_session, args=(session_id, valid_until), daemon=True).start()
                # --- NEW: Schedule firewall close after timeout ---
                threading.Timer(SESSION_TIMEOUT, close_firewall_port, args=[client_ip, TLS_PORT]).start()
                ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ack_sock.sendto(f'SPA_ACCEPTED:{session_id}'.encode(), (client_ip, SPA_ACK_PORT))
                ack_sock.close()
            else:
                print(f"Invalid SPA from {client_ip} ({client_id})")
        except Exception as ex:
            print('SPA parse error:', ex)

if __name__ == "__main__":
    fetch_authorized_spa_keys()
    threading.Thread(target=periodic_refresh, daemon=True).start()
    spa_listener()
