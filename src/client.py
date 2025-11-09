# client.py
#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import queue
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Defaults / env ----------
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
CONTROLLER_HOST = os.environ.get("CONTROLLER_HOST", "sdp-controller")
CONTROLLER_PORT = int(os.environ.get("CONTROLLER_PORT", "8080"))
GATEWAY_SERVICE = os.environ.get("GATEWAY_SERVICE", "sdp-gateway")
UDP_PORT = int(os.environ.get("UDP_PORT", "5005"))
SPA_ACK_PORT = int(os.environ.get("SPA_ACK_PORT", "6000"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "3000"))  # seconds
RESOURCE_PATH = os.environ.get("RESOURCE_PATH", "/api/data")      # path target at gateway

os.makedirs(DATA_DIR, exist_ok=True)

SPA_KEY_PATH = os.path.join(DATA_DIR, "spa_key.bin")
SERVICE_ID_PATH = os.path.join(DATA_DIR, "service_id.bin")
CSV_PATH = os.path.join(DATA_DIR, "spa_latency.csv")

# ---------- Utilities ----------
def log(msg): print(time.strftime("[%Y-%m-%d %H:%M:%S]"), "[CLIENT]", msg)

def registration_files_exist():
    return os.path.exists(SPA_KEY_PATH) and os.path.exists(SERVICE_ID_PATH)

def register(username: str):
    """HTTPS (verify=False) registration with controller; stores SPA key + service_id."""
    url = f"https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register"
    log(f"Registering user '{username}' at {url} (verify=False)")
    r = requests.post(url, json={"username": username}, timeout=5, verify=False)
    r.raise_for_status()
    resp = r.json()
    with open(SPA_KEY_PATH, "wb") as f: f.write(bytes.fromhex(resp["spa_key"]))
    with open(SERVICE_ID_PATH, "wb") as f: f.write(bytes.fromhex(resp["service_id"]))
    log("✔ Registered and saved SPA credentials")

def wait_until_key_synced(username: str, timeout_s: int = 20) -> bool:
    url = f"https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/api/authorized_spa_keys"
    log(f"Waiting up to {timeout_s}s for gateway to sync SPA key …")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2, verify=False)
            r.raise_for_status()
            users = r.json()
            if username in users:
                log("✔ Username is authorized at gateway")
                return True
        except Exception as e:
            pass
        time.sleep(1)
    log("✖ Key did not sync in time")
    return False

def send_spa(username: str):
    """Sends HMAC-SHA256 SPA over UDP to gateway."""
    spa_key = open(SPA_KEY_PATH, "rb").read()
    service_id = open(SERVICE_ID_PATH, "rb").read()
    client_id = username.encode()
    nonce = os.urandom(8)
    timestamp = int(time.time())
    msg = client_id + nonce + struct.pack(">I", timestamp) + service_id
    hmac_val = hmac.new(spa_key, msg, hashlib.sha256).digest()
    packet = msg + hmac_val
    log(f"Sending SPA to {GATEWAY_SERVICE}:{UDP_PORT} …")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (GATEWAY_SERVICE, UDP_PORT))
    sock.close()
    log("✔ SPA sent")

def wait_for_spa_ack(timeout_s: int = 10):
    """Listens on SPA_ACK_PORT (UDP) for SPA_ACCEPTED:session:port:ip"""
    log(f"Waiting for SPA_ACK on UDP {SPA_ACK_PORT} …")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", SPA_ACK_PORT))
    s.settimeout(timeout_s)
    try:
        data, _ = s.recvfrom(1024)
        msg = data.decode(errors="ignore")
        log(f"✔ ACK: {msg}")
        if msg.startswith("SPA_ACCEPTED:"):
            _, session_id, port, ip = msg.strip().split(":")
            return session_id, int(port), ip
    except socket.timeout:
        log("✖ Timeout waiting for SPA ACK")
    finally:
        s.close()
    return None, None, None

# ---------- Load generation ----------
class RateLimiter:
    """Simple token bucket to hit target RPS across multiple workers."""
    def __init__(self, rps: float, burst: int = None):
        self.rps = rps
        self.capacity = burst if burst is not None else max(1, int(rps))
        self.tokens = 0.0
        self.last = time.time()
        self.lock = threading.Lock()

    def wait_for_token(self):
        while True:
            with self.lock:
                now = time.time()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rps)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.001)

def worker(session: requests.Session, url: str, limiter: RateLimiter, runtime_deadline: float, out_q: queue.Queue, timeout_s: float):
    while time.time() < runtime_deadline:
        limiter.wait_for_token()
        t0 = time.perf_counter()
        ok = True
        try:
            r = session.get(url, timeout=timeout_s, verify=False)
            r.raise_for_status()
        except Exception:
            ok = False
        t1 = time.perf_counter()
        out_q.put((ok, (t1 - t0) * 1000.0))

def run_load(base_url: str, path: str, duration_s: int, rps: float, concurrency: int, timeout_s: float):
    target = base_url + path
    log(f"Starting load: {rps} RPS, {concurrency} workers, {duration_s}s → {target}")

    # Connection pooling: large pool to avoid churn
    adapter = requests.adapters.HTTPAdapter(pool_connections=concurrency, pool_maxsize=concurrency*2, max_retries=0)
    sess = requests.Session()
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"Connection": "keep-alive"})

    # Warm-up (don’t count TLS handshake in first datapoint)
    try:
        sess.get(target, timeout=timeout_s, verify=False)
    except Exception:
        pass

    limiter = RateLimiter(rps=rps, burst=max(1, int(rps)))
    out_q = queue.Queue()
    deadline = time.time() + duration_s

    with ThreadPoolExecutor(max_workers=concurrency) as tp:
        futures = [tp.submit(worker, sess, target, limiter, deadline, out_q, timeout_s) for _ in range(concurrency)]
        for f in as_completed(futures):  # wait for all
            pass

    sess.close()

    # Drain queue
    results = []
    while not out_q.empty():
        results.append(out_q.get())

    return results

def summarize_and_write_csv(results, csv_path: str):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    successes = [lat for ok, lat in results if ok]
    fails = len(results) - len(successes)

    # Write CSV
    with open(csv_path, "w") as f:
        f.write("index,latency_ms,success\n")
        for i, (ok, lat) in enumerate(results, 1):
            f.write(f"{i},{lat:.3f},{'yes' if ok else 'no'}\n")

    if successes:
        successes.sort()
        def pct(p):  # p in [0,100]
            idx = min(len(successes)-1, max(0, int(round((p/100.0)*(len(successes)-1)))))
            return successes[idx]
        summary = {
            "count": len(results),
            "success": len(successes),
            "fail": fails,
            "min_ms": successes[0],
            "p50_ms": pct(50),
            "p90_ms": pct(90),
            "p99_ms": pct(99),
            "max_ms": successes[-1],
            "avg_ms": mean(successes),
        }
    else:
        summary = {
            "count": len(results),
            "success": 0,
            "fail": fails,
            "min_ms": None,
            "p50_ms": None,
            "p90_ms": None,
            "p99_ms": None,
            "max_ms": None,
            "avg_ms": None,
        }

    log("==== Results ====")
    log(json.dumps(summary, indent=2))
    log(f"CSV written: {csv_path}")
    return summary

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="SDP client load generator (keep-alive HTTPS via gateway)")
    ap.add_argument("--username", default="aliceIH")
    ap.add_argument("--rps", type=float, default=100.0, help="Target requests per second")
    ap.add_argument("--duration", type=int, default=60, help="Test duration seconds")
    ap.add_argument("--concurrency", type=int, default=10, help="Number of worker threads")
    ap.add_argument("--timeout", type=float, default=2.0, help="Per-request timeout seconds")
    ap.add_argument("--csv", default=CSV_PATH, help="CSV output path")
    args = ap.parse_args()

    if not registration_files_exist():
        register(args.username)
        time.sleep(1)

    if not wait_until_key_synced(args.username, timeout_s=20):
        raise SystemExit(1)

    send_spa(args.username)
    session_id, port, ip = wait_for_spa_ack(timeout_s=10)
    if not port:
        raise SystemExit("Did not receive SPA_ACCEPTED")

    base_url = f"https://{ip}:{port}"
    log(f"Gateway session {session_id} at {base_url} (verify=False)")

    results = run_load(
        base_url=base_url,
        path=RESOURCE_PATH,
        duration_s=args.duration,
        rps=args.rps,
        concurrency=args.concurrency,
        timeout_s=args.timeout,
    )
    summarize_and_write_csv(results, args.csv)

if __name__ == "__main__":
    main()
