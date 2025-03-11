import argparse
from scanner.nmap_scan import nmap_scan
from scanner.scapy_scan import scapy_scan
from scanner.vulnerability_check import check_vulnerabilities
from scanner.report_generator import save_report, save_csv

def main():
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("--csv", action="store_true", help="Save report as CSV")
    
    args = parser.parse_args()
    
    print(f"Scanning {args.target}...")
    scan_results = nmap_scan(args.target)
    
    print("Analyzing vulnerabilities...")
    vulnerabilities = check_vulnerabilities(scan_results)
    
    print("Generating report...")
    save_report(vulnerabilities)
    if args.csv:
        save_csv(vulnerabilities)
    
    print("Scan complete. Report saved.")

if __name__ == "__main__":
    main()
