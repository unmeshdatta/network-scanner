import unittest
from scanner.scanner import NetworkScanner
from scanner.nmap_scan import nmap_scan
from scanner.scapy_scan import scapy_scan
from scanner.vulnerability_check import check_vulnerabilities
import os
import json
import csv

class TestNetworkScanner(unittest.TestCase):

    def setUp(self):
        """Set up test cases with a sample IP."""
        self.target_ip = "127.0.0.1"  # Using localhost for safe testing
        self.scanner = NetworkScanner(self.target_ip)

    def test_nmap_scan(self):
        """Test if Nmap scan returns expected data format."""
        result = nmap_scan(self.target_ip)
        self.assertIsInstance(result, dict)
        self.assertIn(self.target_ip, result)

    def test_scapy_scan(self):
        """Test if Scapy scan returns a valid response."""
        result = scapy_scan(self.target_ip)
        self.assertIsInstance(result, dict)

    def test_vulnerability_analysis(self):
        """Check if vulnerabilities are detected correctly."""
        scan_results = {self.target_ip: {22: {"name": "OpenSSH", "version": "8.2"}}}
        vulnerabilities = check_vulnerabilities(scan_results)
        self.assertIsInstance(vulnerabilities, dict)
        self.assertIn(self.target_ip, vulnerabilities)

    def test_generate_json_report(self):
        """Ensure JSON report is correctly saved."""
        vulnerabilities = {self.target_ip: ["Port 22: SSH - Check for weak credentials"]}
        self.scanner.generate_report(vulnerabilities)
        self.assertTrue(os.path.exists("report.json"))

        # Validate JSON structure
        with open("report.json", "r") as f:
            data = json.load(f)
            self.assertIsInstance(data, dict)

    def test_generate_csv_report(self):
        """Ensure CSV report is correctly saved."""
        vulnerabilities = {self.target_ip: ["Port 22: SSH - Check for weak credentials"]}
        self.scanner.output_format = "csv"
        self.scanner.generate_report(vulnerabilities)
        self.assertTrue(os.path.exists("report.csv"))

        # Validate CSV structure
        with open("report.csv", "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
            self.assertGreater(len(rows), 1)  # At least header + one row

    def tearDown(self):
        """Clean up generated test reports."""
        if os.path.exists("report.json"):
            os.remove("report.json")
        if os.path.exists("report.csv"):
            os.remove("report.csv")

if __name__ == "__main__":
    unittest.main()
