import requests

def check_security_headers(url):
    """Checks important security headers and server info leakage."""
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

        results = [f"[+] Final URL after redirects: {response.url}"]

        for header, description in security_headers.items():
            if header in headers:
                results.append(f"[+] {header} is correctly implemented.")
            else:
                results.append(f"[!] Missing {header}: {description}")

        if "Strict-Transport-Security" not in headers:
            preload_check = requests.get(f"https://hstspreload.org/api/v2/status?domain={url.split('//')[1].split('/')[0]}")
            if preload_check.status_code == 200 and '"status":"preloaded"' in preload_check.text:
                results.append("[+] HSTS is preloaded in browsers.")

        # Server Information Leakage Detection
        info_leakage_headers = ["Server", "X-Powered-By", "Via", "X-AspNet-Version"]
        for leak_header in info_leakage_headers:
            if leak_header in headers:
                leakage = headers[leak_header]
                results.append(f"[!] Server Information Leakage Detected: {leak_header}: {leakage}")

        return results
    except requests.exceptions.RequestException as e:
        return [f"[!] Failed to fetch headers: {str(e)}"]
