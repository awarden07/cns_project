import requests

def check_security_headers(url):
    """Checks important security headers and server info leakage."""
    results = []

    try:
        if not url.startswith("https://"):
            url = "https://" + url.lstrip("http://")

        session = requests.Session()
        response = session.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": "HSTS (Enforces HTTPS)",
            "X-Frame-Options": "Prevents Clickjacking",
            "Content-Security-Policy": "Prevents XSS & Data Injection",
            "X-Content-Type-Options": "Blocks MIME-type attacks"
        }

        results.append({
            "issue": f"Final URL after redirects: {response.url}",
            "severity": "Low"
        })

        for header, description in security_headers.items():
            if header in headers:
                results.append({
                    "issue": f"{header} is correctly implemented.",
                    "severity": "Low"
                })
            else:
                results.append({
                    "issue": f"Missing {header}: {description}",
                    "severity": "Medium"
                })

        # HSTS preload check if header missing
        if "Strict-Transport-Security" not in headers:
            domain = url.split("//")[1].split("/")[0]
            try:
                preload_check = requests.get(f"https://hstspreload.org/api/v2/status?domain={domain}")
                if preload_check.status_code == 200 and '"status":"preloaded"' in preload_check.text:
                    results.append({
                        "issue": "HSTS is preloaded in browsers.",
                        "severity": "Low"
                    })
            except requests.RequestException:
                results.append({
                    "issue": "Failed to check HSTS preload status.",
                    "severity": "Low"
                })

        # Server Information Leakage
        info_leakage_headers = ["Server", "X-Powered-By", "Via", "X-AspNet-Version"]
        for leak_header in info_leakage_headers:
            if leak_header in headers:
                leakage = headers[leak_header]
                results.append({
                    "issue": f"Server Information Leakage Detected: {leak_header}: {leakage}",
                    "severity": "Low"
                })

    except requests.exceptions.RequestException as e:
        results.append({
            "issue": f"Failed to fetch headers: {str(e)}",
            "severity": "Low"
        })

    return results
