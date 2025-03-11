import argparse
from scanner.nmap_scan import nmap_scan
from scanner.scapy_scan import scapy_scan
from scanner.vulnerability_check import check_vulnerabilities
from scanner.report_generator import save_report, save_csv

class NetworkScanner:
    def __init__(self, target, use_scapy=False, output_format="json"):
        self.target = target
        self.use_scapy = use_scapy
        self.output_format = output_format
        self.scan_results = {}

    def run_scan(self):
        print(f"Scanning {self.target}...")

        # Perform Nmap scan
        self.scan_results = nmap_scan(self.target)

        # Optionally run Scapy scan
        if self.use_scapy:
            print("Running Scapy scan for deeper analysis...")
            scapy_results = scapy_scan(self.target)
            self.scan_results.update(scapy_results)

        print("Scan complete.")
        return self.scan_results

    def analyze_vulnerabilities(self):
        print("Analyzing vulnerabilities...")
        vulnerabilities = check_vulnerabilities(self.scan_results)
        return vulnerabilities

    def generate_report(self, vulnerabilities):
        print("Generating report...")
        if self.output_format == "json":
            save_report(vulnerabilities)
        elif self.output_format == "csv":
            save_csv(vulnerabilities)

    def run(self):
        self.run_scan()
        vulnerabilities = self.analyze_vulnerabilities()
        self.generate_report(vulnerabilities)
        print("Report saved successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("--scapy", action="store_true", help="Use Scapy for additional packet analysis")
    parser.add_argument("--csv", action="store_true", help="Save report as CSV instead of JSON")

    args = parser.parse_args()
    scanner = NetworkScanner(target=args.target, use_scapy=args.scapy, output_format="csv" if args.csv else "json")
    scanner.run()
