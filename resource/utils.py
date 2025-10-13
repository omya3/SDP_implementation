import subprocess
import threading


def open_temporary_port(client_ip, port=8100, timeout=30):
    subprocess.run([
        "sudo", "iptables", "-I", "INPUT", "1",
        "-p", "tcp", "--dport", str(port), "-s", client_ip, "-j", "ACCEPT"
    ], check=True)
    def remove_rule():
        subprocess.run([
            "sudo", "iptables", "-D", "INPUT",
            "-p", "tcp", "--dport", str(port), "-s", client_ip, "-j", "ACCEPT"
        ], check=True)
    threading.Timer(timeout, remove_rule).start()
