from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    ans, _ = sr(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2, verbose=False)
    return port if ans else None

def scapy_scan(target):
    ports = [22, 80, 443]
    results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        scan_results = executor.map(lambda port: scan_port(target, port), ports)

    results[target] = [port for port in scan_results if port]
    return results
