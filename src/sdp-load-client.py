#!/usr/bin/env python3
import argparse, hashlib, hmac, json, os, queue, socket, struct, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DATA_DIR        = os.getenv("DATA_DIR", "/app/data")
CONTROLLER_HOST = os.getenv("CONTROLLER_HOST", "sdp-controller")
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "8080"))
GATEWAY_SERVICE = os.getenv("GATEWAY_SERVICE", "sdp-gateway")
UDP_PORT        = int(os.getenv("UDP_PORT", "5005"))
SPA_ACK_PORT    = int(os.getenv("SPA_ACK_PORT", "6000"))
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3000"))
RESOURCE_PATH   = os.getenv("RESOURCE_PATH", "/api/data")

SPA_KEY_PATH    = os.path.join(DATA_DIR, "spa_key.bin")
SERVICE_ID_PATH = os.path.join(DATA_DIR, "service_id.bin")

os.makedirs(DATA_DIR, exist_ok=True)

def log(m): print(time.strftime("[%Y-%m-%d %H:%M:%S]"), "[CLIENT]", m)

def registration_files_exist():
    return os.path.exists(SPA_KEY_PATH) and os.path.exists(SERVICE_ID_PATH)

def register(username):
    r = requests.post(f"https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/register",
                      json={"username": username}, verify=False)
    r.raise_for_status()
    data = r.json()
    open(SPA_KEY_PATH, "wb").write(bytes.fromhex(data["spa_key"]))
    open(SERVICE_ID_PATH, "wb").write(bytes.fromhex(data["service_id"]))
    log("✔ Registered")

def wait_until_key_synced(username, timeout=20):
    deadline = time.time()+timeout
    while time.time() < deadline:
        try:
            if username in requests.get(
                f"https://{CONTROLLER_HOST}:{CONTROLLER_PORT}/api/authorized_spa_keys",
                verify=False).json():
                log("✔ Key synced")
                return True
        except: pass
        time.sleep(1)
    log("✖ Key sync timeout"); return False

def send_spa_and_wait_ack(username):
    ack = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ack.bind(("0.0.0.0", SPA_ACK_PORT))
    ack.settimeout(0.5)

    spa = open(SPA_KEY_PATH,"rb").read()
    sid = open(SERVICE_ID_PATH,"rb").read()
    cid = username.encode()
    n = os.urandom(8)
    ts = int(time.time())
    msg = cid+n+struct.pack(">I",ts)+sid
    pkt = msg + hmac.new(spa,msg,hashlib.sha256).digest()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    end = time.time()+10
    while time.time()<end:
        s.sendto(pkt,(GATEWAY_SERVICE,UDP_PORT))
        log("Sent SPA → waiting for ACK…")
        try:
            data,_ = ack.recvfrom(1024)
            parts = data.decode().split(":")
            if parts[0]=="SPA_ACCEPTED":
                ack.close(); s.close()
                return parts[1], int(parts[2]), parts[3]
        except socket.timeout:
            continue
    ack.close(); s.close()
    return None,None,None

class RateLimiter:
    def __init__(self,rps):
        self.rps=rps; self.tokens=0; self.last=time.time()
    def wait(self):
        while True:
            now=time.time()
            self.tokens += (now-self.last)*self.rps
            self.last=now
            if self.tokens>=1:
                self.tokens-=1; return
            time.sleep(0.001)

def worker(sess,url,limiter,end,timeout,q):
    while time.time()<end:
        limiter.wait()
        t0=time.perf_counter()
        ok=True
        try:
            r=sess.get(url,timeout=timeout,verify=False)
            r.raise_for_status()
        except: ok=False
        q.put((ok,(time.perf_counter()-t0)*1000))

def run_load(base_url,path,rps,duration,conc,timeout,csv):
    url=base_url+path
    sess=requests.Session()
    sess.mount("https://",requests.adapters.HTTPAdapter(pool_connections=conc,pool_maxsize=conc*2))
    try: sess.get(url,timeout=timeout,verify=False)
    except: pass

    limiter=RateLimiter(rps)
    end=time.time()+duration
    q=queue.Queue()

    with ThreadPoolExecutor(max_workers=conc) as pool:
        for _ in range(conc):
            pool.submit(worker,sess,url,limiter,end,timeout,q)

    results=[]
    while not q.empty(): results.append(q.get())

    ok=[lat for s,lat in results if s]
    ok.sort()
    def p(x): return ok[int(len(ok)*x)-1] if ok else None
    summary={"count":len(results),"success":len(ok),"fail":len(results)-len(ok),
             "p50":p(0.5),"p90":p(0.9),"p99":p(0.99),
             "avg":mean(ok) if ok else None}
    log(json.dumps(summary,indent=2))
    with open(csv,"w") as f:
        f.write("ok,latency_ms\n")
        for s,l in results: f.write(f"{1 if s else 0},{l:.3f}\n")
    log("CSV written → "+csv)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--username",default="aliceIH")
    p.add_argument("--rps",type=float,default=5)
    p.add_argument("--duration",type=int,default=60)
    p.add_argument("--concurrency",type=int,default=4)
    p.add_argument("--timeout",type=float,default=2.0)
    p.add_argument("--csv",default="/app/data/spa_latency.csv")
    a=p.parse_args()

    if not registration_files_exist(): register(a.username)
    if not wait_until_key_synced(a.username): return
    sid,port,ip = send_spa_and_wait_ack(a.username)
    if not port: log("No ACK"); return
    run_load(f"https://{ip}:{port}",RESOURCE_PATH,a.rps,a.duration,a.concurrency,a.timeout,a.csv)

if __name__=="__main__": main()
