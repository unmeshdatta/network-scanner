import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

def get_cve_info(service_name, version):
    query = f"{service_name} {version}"
    params = {"keyword": query, "resultsPerPage": 5}
    response = requests.get(NVD_API_URL, params=params)
    
    if response.status_code == 200:
        cve_data = response.json()
        return [
            (cve["cve"]["CVE_data_meta"]["ID"], cve["cve"]["description"]["description_data"][0]["value"])
            for cve in cve_data.get("result", {}).get("CVE_Items", [])
        ]
    return []

if __name__ == "__main__":
    print(get_cve_info("OpenSSH", "8.2"))
