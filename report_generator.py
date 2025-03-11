import json
import csv

def save_report(data, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def save_csv(data, filename="report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Issue"])
        for host, issues in data.items():
            for issue in issues:
                writer.writerow([host, issue])
