from flask import Flask, render_template, request, jsonify
from scanner.nmap_scan import nmap_scan
from scanner.scapy_scan import scapy_scan
from scanner.vulnerability_check import check_vulnerabilities
from scanner.report_generator import save_report, save_csv

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form["target"]
        scan_results = nmap_scan(target)
        vulnerabilities = check_vulnerabilities(scan_results)
        save_report(vulnerabilities)
        return render_template("index.html", scan_results=scan_results, vulnerabilities=vulnerabilities)
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
