import nmap
from concurrent.futures import ThreadPoolExecutor

def scan_host(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments="-sV -Pn")
    return nm[host].get("tcp", {})

def nmap_scan(target):
    hosts = target.split(",")  # Support multiple IPs
    results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        scan_results = executor.map(scan_host, hosts)
    
    for host, scan_result in zip(hosts, scan_results):
        results[host] = scan_result

    return results
