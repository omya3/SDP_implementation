import hashlib
import hmac
import os
import socket
import struct
import time
import requests
import csv
import random
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [CLIENT] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

data_dir = "/app/data"
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

CONTROLLER_HOST = 'sdp-controller'
CONTROLLER_PORT = 8080
GATEWAY_SERVICE = 'sdp-gateway'
UDP_PORT = 5005
SPA_ACK_PORT = 6000
SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 600))  # 10 minutes

logger.info("Protocol Specification:")
logger.info("  ✅ HTTPS to Controller (self-signed, unverified)")
logger.info("  ✅ UDP SPA packet (unencrypted, HMAC-signed)")
logger.info("  ✅ HTTP to Gateway (no TLS)")
logger.info(f"  ✅ SESSION_TIMEOUT: {SESSION_TIMEOUT} seconds")

def registration_files_exist():
    return (
        os.path.exists(os.path.join(data_dir, 'spa_key.bin')) and
        os.path.exists(os.path.join(data_dir, 'service_id.bin'))
    )

def register(username):
    """Register with controller and get SPA credentials"""
    try:
        resp = requests.post(
            f'https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register',
            json={'username': username},
            verify=False,
            timeout=5
        ).json()
        
        with open(os.path.join(data_dir, 'spa_key.bin'), 'wb') as f:
            f.write(bytes.fromhex(resp['spa_key']))
        
        with open(os.path.join(data_dir, 'service_id.bin'), 'wb') as f:
            f.write(bytes.fromhex(resp['service_id']))
        
        logger.info(f"Registered: {username}")
        logger.info(f"SPA Key: {resp['spa_key'][:16]}...")
        logger.info(f"Service ID: {resp['service_id'][:16]}...")
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise

def wait_until_key_synced(username, timeout=20):
    """Wait for controller to sync SPA keys to gateway"""
    logger.info(f"Waiting for gateway key sync ({timeout}s)...")
    for i in range(timeout):
        try:
            resp = requests.get(
                f'https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/api/authorized_spa_keys', 
                timeout=2,
                verify=False
            )
            users = resp.json()
            if username in users:
                logger.info(f"✅ Username {username} is now authorized!")
                return True
        except Exception as e:
            logger.debug(f"Sync check attempt {i+1} failed: {e}")
            pass
        time.sleep(1)
    logger.error(f"Timeout: SPA key never appeared in gateway!")
    return False

def send_spa(username):
    """Send SPA packet to gateway"""
    try:
        client_id = username.encode()
        nonce = os.urandom(8)
        timestamp = int(time.time())
        service_id_path = os.path.join(data_dir, 'service_id.bin')
        spa_key_path = os.path.join(data_dir, 'spa_key.bin')
        
        if not os.path.exists(service_id_path) or not os.path.exists(spa_key_path):
            logger.error("Missing registration files!")
            return
        
        service_id = open(service_id_path, 'rb').read()
        spa_key = open(spa_key_path, 'rb').read()
        msg = client_id + nonce + struct.pack(">I", timestamp) + service_id
        hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest()
        packet = msg + hmac_val
        
        logger.info(f"Sending UDP SPA packet to {GATEWAY_SERVICE}:{UDP_PORT}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (GATEWAY_SERVICE, UDP_PORT))
        logger.info(f"✅ SPA sent!")
    except Exception as e:
        logger.error(f"Failed to send SPA: {e}")
        raise

def wait_for_spa_ack():
    """Wait for gateway ACK response"""
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ack_sock.bind(('0.0.0.0', SPA_ACK_PORT))
    except Exception as e:
        logger.error(f"Failed to bind ACK port: {e}")
        return None, None, None
    ack_sock.settimeout(10)
    logger.info(f"Waiting for SPA_ACK on UDP {SPA_ACK_PORT}...")
    try:
        data, addr = ack_sock.recvfrom(1024)
        msg = data.decode(errors="ignore")
        logger.info(f"✅ Received ACK: {msg}")
        if msg.startswith('SPA_ACCEPTED:'):
            fields = msg.split(':')
            if len(fields) >= 4:
                return fields[1], int(fields[2]), fields[3]
    except socket.timeout:
        logger.error("Timeout waiting for ACK!")
    finally:
        ack_sock.close()
    return None, None, None

def access_service(username):
    """Main load test: send requests and measure latency"""
    if not wait_until_key_synced(username):
        logger.error("Aborting!")
        return
    
    send_spa(username)
    session_id, http_port, gateway_pod_ip = wait_for_spa_ack()
    
    if http_port is None:
        logger.error("No port in ACK!")
        return
    
    logger.info(f"Connecting to {gateway_pod_ip}:{http_port} (HTTP)...")
    results = []
    start_time_window = time.time()
    request_count = 0
    
    while time.time() - start_time_window < SESSION_TIMEOUT:
        try:
            request_count += 1
            request_start = time.perf_counter()  # High precision timer
            
            sock = socket.create_connection((gateway_pod_ip, http_port), timeout=5)
            
            req = b"GET /api/data HTTP/1.1\r\nHost: sdp-resource\r\nConnection: close\r\n\r\n"
            sock.send(req)
            resp = sock.recv(4096).decode(errors='ignore')
            
            request_end = time.perf_counter()  # High precision timer
            latency_ms = (request_end - request_start) * 1000
            
            results.append(latency_ms)
            logger.debug(f"Request #{request_count}: {latency_ms:.2f} ms")
            sock.close()
            
        except Exception as e:
            logger.warning(f"Request #{request_count} failed: {e}")
            results.append(None)
        
        time.sleep(0.3 + random.expovariate(1/0.5))  # Real-world traffic pattern
    
    # Statistics
    valid_latencies = [l for l in results if l is not None]
    failed_count = len(results) - len(valid_latencies)
    
    if valid_latencies:
        avg = sum(valid_latencies) / len(valid_latencies)
        std_dev = (sum((x - avg) ** 2 for x in valid_latencies) / len(valid_latencies)) ** 0.5
        
        logger.info(f"\n{'='*60}")
        logger.info(f"[Load Test Statistics] - SESSION_TIMEOUT: {SESSION_TIMEOUT}s")
        logger.info(f"{'='*60}")
        logger.info(f"Total Requests:    {len(results)}")
        logger.info(f"Successful:        {len(valid_latencies)}")
        logger.info(f"Failed:            {failed_count} ({100*failed_count/len(results):.1f}%)")
        logger.info(f"Min latency:       {min(valid_latencies):.2f} ms")
        logger.info(f"Max latency:       {max(valid_latencies):.2f} ms")
        logger.info(f"Average:           {avg:.2f} ms")
        logger.info(f"Std Deviation:     {std_dev:.2f} ms")
        logger.info(f"{'='*60}\n")
    else:
        logger.error("No valid latency measurements!")
    
    # CSV output
    csv_path = os.path.join(data_dir, "spa_latency.csv")
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["request#", "latency_ms", "success"])
        for i, r in enumerate(results):
            success = "yes" if r is not None else "no"
            writer.writerow([i+1, f"{r:.2f}" if r is not None else "fail", success])
    logger.info(f"Latency results saved in {csv_path}")

if __name__ == "__main__":
    username = 'aliceIH'
    if not registration_files_exist():
        logger.info("Registering...")
        register(username)
        time.sleep(2)
    access_service(username)
