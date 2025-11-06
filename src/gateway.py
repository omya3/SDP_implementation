import hashlib
import hmac
import secrets
import socket
import struct
import threading
import time
import requests
import os
import sys
import traceback
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [GATEWAY] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

SERVER_HOST = '0.0.0.0'
UDP_PORT = 5005
SPA_ACK_PORT = 6000
RESOURCE_HOST = 'sdp-resource'
RESOURCE_PORT = 8100
SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 600))  # 10 minutes
CONTROLLER_URL = 'https://sdp-controller:8080'
AUTHORIZED_SPAS = {}

logger.info("Protocol Specification:")
logger.info("  ✅ UDP SPA packet (unencrypted, HMAC-signed)")
logger.info("  ✅ HTTP proxy tunnel to clients (no TLS)")
logger.info("  ✅ HTTPS to Controller (self-signed, unverified)")
logger.info("  ✅ HTTP to Resource (internal only)")
logger.info(f"  ✅ SESSION_TIMEOUT: {SESSION_TIMEOUT} seconds")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

def fetch_authorized_spa_keys():
    global AUTHORIZED_SPAS
    try:
        resp = requests.get(f"{CONTROLLER_URL}/api/authorized_spa_keys", timeout=3, verify=False)
        AUTHORIZED_SPAS = {user: bytes.fromhex(spa) for user, spa in resp.json().items()}
        logger.debug(f"Fetched authorized SPA keys: {list(AUTHORIZED_SPAS.keys())}")
    except Exception as e:
        logger.warning(f"Failed to fetch SPA keys: {e}")

def periodic_refresh():
    while True:
        fetch_authorized_spa_keys()
        time.sleep(3)

def tcp_forward(client_sock, resource_host, resource_port, valid_until):
    backend_sock = None
    try:
        backend_sock = socket.create_connection((resource_host, resource_port))
        
        def tunnel(source, dest, name):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    dest.sendall(data)
            except Exception as e:
                logger.debug(f"Tunnel {name} closed: {e}")
            finally:
                try: source.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: dest.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                source.close()
                dest.close()
        
        def session_timeout_killer():
            time.sleep(max(0, valid_until - time.time()))
            try: client_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: backend_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            if client_sock: client_sock.close()
            if backend_sock: backend_sock.close()
        
        threading.Thread(target=tunnel, args=(client_sock, backend_sock, "c2b"), daemon=True).start()
        threading.Thread(target=tunnel, args=(backend_sock, client_sock, "b2c"), daemon=True).start()
        threading.Thread(target=session_timeout_killer, daemon=True).start()
        
    except Exception as e:
        logger.error(f"TCP Proxy error: {e}")
        if client_sock:
            try: client_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            client_sock.close()
        if backend_sock:
            try: backend_sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            backend_sock.close()

def start_http_proxy_server(session_id, valid_until, port_ready_event, port_holder):
    """HTTP proxy tunnel to client (no TLS)"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 0))
    _, http_port = server_sock.getsockname()
    server_sock.listen(1)
    port_holder['port'] = http_port
    port_ready_event.set()
    
    logger.info(f"HTTP proxy for session {session_id} listening on port {http_port}")
    
    accept_deadline = valid_until
    while time.time() < accept_deadline:
        try:
            left = accept_deadline - time.time()
            server_sock.settimeout(left if left > 0 else 1)
            
            try:
                client_sock, addr = server_sock.accept()
                logger.info(f"Accepted HTTP connection from {addr}")
                threading.Thread(target=tcp_forward, args=(client_sock, RESOURCE_HOST, RESOURCE_PORT, valid_until), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.warning(f"Accept error: {e}")
                continue
        except Exception as e:
            logger.error(f"Proxy error: {e}")
    
    server_sock.close()
    logger.info(f"Session {session_id} proxy window closed.")

def spa_listener():
    """UDP SPA listener (unencrypted, HMAC-signed)"""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SERVER_HOST, UDP_PORT))
    logger.info(f'Listening for SPA packets on UDP {UDP_PORT} (unencrypted, HMAC-signed)...')
    
    while True:
        try:
            data, addr = udp_sock.recvfrom(4096)
            client_ip, _ = addr
            logger.info(f"Received SPA packet from {client_ip} ({len(data)} bytes)")
            
            matched_id = None
            for user in AUTHORIZED_SPAS:
                user_bytes = user.encode()
                if data.startswith(user_bytes):
                    matched_id = user
                    break
            
            if matched_id is None:
                logger.warning(f"[REJECT] Could not match SPA to any authorized user from {client_ip}")
                continue
            
            client_id = matched_id
            spa_key = AUTHORIZED_SPAS[client_id]
            id_len = len(client_id.encode())
            
            nonce = data[id_len:id_len+8]
            timestamp = struct.unpack(">I", data[id_len+8:id_len+12])[0]
            service_id = data[id_len+12:id_len+28]
            hmac_recv = data[id_len+28:]
            msg = data[:id_len+28]
            
            hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest()
            now = time.time()
            
            if hmac_val == hmac_recv and abs(now - timestamp) < SESSION_TIMEOUT:
                session_id = secrets.token_hex(8)
                valid_until = now + SESSION_TIMEOUT
                port_ready_event = threading.Event()
                port_holder = {}
                
                t = threading.Thread(target=start_http_proxy_server, args=(session_id, valid_until, port_ready_event, port_holder), daemon=True)
                t.start()
                port_ready_event.wait()
                
                http_port = port_holder['port']
                pod_ip = socket.gethostbyname(socket.gethostname())
                
                ack_msg = f'SPA_ACCEPTED:{session_id}:{http_port}:{pod_ip}'
                ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ack_sock.sendto(ack_msg.encode(), (client_ip, SPA_ACK_PORT))
                ack_sock.close()
                
                logger.info(f"[ACCEPT] Valid SPA from {client_ip} (user: {client_id}), session {session_id}, HTTP port {http_port}")
            else:
                logger.warning(f"[REJECT] Invalid SPA from {client_ip} (hmac or timestamp mismatch)")
        
        except Exception as ex:
            logger.error(f"SPA parse error: {ex}\n{traceback.format_exc()}")

if __name__ == "__main__":
    fetch_authorized_spa_keys()
    threading.Thread(target=periodic_refresh, daemon=True).start()
    spa_listener()
