import hashlib
import hmac
import secrets
import socket
import struct
import subprocess
import threading
import time
import requests
import ssl

SERVER_HOST = '0.0.0.0'
UDP_PORT = 5005
SPA_ACK_PORT = 6000
RESOURCE_HOST = 'localhost'
RESOURCE_PORT = 8100
SESSION_TIMEOUT = 60
CONTROLLER_URL = 'http://localhost:8080'

AUTHORIZED_SPAS = {}

def open_firewall_port(client_ip, port):
    cmd = [
        "sudo", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port),
        "-s", client_ip, "-j", "ACCEPT"
    ]
    print("Opening firewall port for", client_ip, "on", port)
    subprocess.run(cmd, check=True)

def close_firewall_port(client_ip, port):
    cmd = [
        "sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
        "-s", client_ip, "-j", "ACCEPT"
    ]
    print("Closing firewall port for", client_ip, "on", port)
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
        time.sleep(3)

def tcp_forward(client_sock, resource_host, resource_port, valid_until):
    try:
        # Plain HTTP: connect directly, do NOT wrap in SSL
        backend_sock = socket.create_connection((resource_host, resource_port))

        def tunnel(source, dest):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    dest.sendall(data)
            except Exception:
                pass
            finally:
                try: source.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: dest.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                source.close()
                dest.close()

        def session_timeout_killer():
            time.sleep(max(0, valid_until - time.time()))
            print("Proxy: Closing sockets due to session timeout")
            try: client_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: backend_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            client_sock.close()
            backend_sock.close()

        threading.Thread(target=tunnel, args=(client_sock, backend_sock), daemon=True).start()
        threading.Thread(target=tunnel, args=(backend_sock, client_sock), daemon=True).start()
        threading.Thread(target=session_timeout_killer, daemon=True).start()

    except Exception as e:
        print("TCP Proxy error:", e)
        client_sock.close()


def start_tls_proxy_server(session_id, valid_until, port_ready_event, port_holder):
    gw_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    gw_context.load_cert_chain('gw_cert.pem', 'gw_key.pem')
    gw_context.load_verify_locations(cafile='ca_cert.pem')
    gw_context.verify_mode = ssl.CERT_REQUIRED
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, 0))
    _, tls_port = server_sock.getsockname()
    port_holder['port'] = tls_port
    port_ready_event.set()
    server_sock.listen(1)
    print(f"Gateway proxy for session {session_id} on port {tls_port}")
    accept_deadline = valid_until
    while time.time() < accept_deadline:
        try:
            server_sock.settimeout(accept_deadline - time.time())
            client_sock, addr = server_sock.accept()
            ssl_client_sock = gw_context.wrap_socket(client_sock, server_side=True)
            print(f"Proxy: Accepted for session {session_id} from {addr}")
            threading.Thread(target=tcp_forward, args=(ssl_client_sock, RESOURCE_HOST, RESOURCE_PORT, valid_until), daemon=True).start()
        except socket.timeout:
            break
        except Exception as e:
            print("TCP proxy accept error:", e)
            continue
    server_sock.close()
    print(f"Session {session_id} proxy window closed.")

def spa_listener():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SERVER_HOST, UDP_PORT))
    print('AH: Listening for SPA...')
    while True:
        data, addr = udp_sock.recvfrom(4096)
        client_ip, _ = addr
        print("\nReceived SPA packet from", client_ip)
        print("Full SPA packet (hex):", data.hex())
        try:
            matched_id = None
            for user in AUTHORIZED_SPAS:
                user_bytes = user.encode()
                if data.startswith(user_bytes):
                    matched_id = user
                    break
            print("Currently authorized users:", list(AUTHORIZED_SPAS.keys()))
            if matched_id is None:
                print("[REJECT] Could not match SPA start to any username in AUTHORIZED_SPAS.")
                print("First 32 bytes of data:", data[:32], "as str:", data[:32].decode(errors='ignore'))
                continue
            client_id = matched_id
            spa_key = AUTHORIZED_SPAS[client_id]
            id_len = len(client_id.encode())
            nonce = data[id_len:id_len+8]
            timestamp = struct.unpack(">I", data[id_len+8:id_len+12])[0]
            service_id = data[id_len+12:id_len+28]
            hmac_recv = data[id_len+28:]
            msg = data[:id_len+28]
            print(f"client_id='{client_id}', length={id_len}, nonce(hex)={nonce.hex()}, timestamp={timestamp}, service_id(hex)={service_id.hex()}")
            print("spa_key(hex):", spa_key.hex())
            print("hmac_recv(hex):", hmac_recv.hex())
            hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest() if spa_key else None
            print("expected hmac(hex):", hmac_val.hex() if hmac_val else None)
            now = time.time()
            if hmac_val == hmac_recv and abs(now - timestamp) < SESSION_TIMEOUT:
                session_id = secrets.token_hex(8)
                valid_until = now + SESSION_TIMEOUT
                port_ready_event = threading.Event()
                port_holder = {}
                t = threading.Thread(target=start_tls_proxy_server, args=(session_id, valid_until, port_ready_event, port_holder), daemon=True)
                t.start()
                port_ready_event.wait()
                tls_port = port_holder['port']
                open_firewall_port(client_ip, tls_port)
                threading.Timer(SESSION_TIMEOUT, close_firewall_port, args=[client_ip, tls_port]).start()
                ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ack_sock.sendto(f'SPA_ACCEPTED:{session_id}:{tls_port}'.encode(), (client_ip, SPA_ACK_PORT))
                ack_sock.close()
                print(f"\033[92m[ACCEPT] Valid SPA from {client_ip} (username: {client_id}), session {session_id}, port {tls_port}\033[0m")
            else:
                print(f"\033[91m[REJECT] Invalid SPA: hmac or timestamp invalid\033[0m")
                if hmac_val != hmac_recv:
                    print("[REJECT REASON] HMAC mismatch")
                if abs(now - timestamp) >= SESSION_TIMEOUT:
                    print("[REJECT REASON] Timestamp difference too large (anti-replay)")
        except Exception as ex:
            print(f"\033[91mSPA parse error:\033[0m", ex)

if __name__ == "__main__":
    fetch_authorized_spa_keys()
    threading.Thread(target=periodic_refresh, daemon=True).start()
    spa_listener()
    