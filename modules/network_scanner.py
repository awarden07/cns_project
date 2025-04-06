import socket
import requests
import urllib.parse

COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 8080, 8443]

def scan_open_ports(host):
    open_ports = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def grab_banner(host, port):
    """Attempts to grab a service banner from an open port."""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        if banner:
            return f"[+] Banner for {host}:{port} -> {banner}"
        else:
            return f"[!] No banner detected for {host}:{port}"
    except Exception:
        return f"[!] Unable to grab banner for {host}:{port}"

def get_http_methods(url):
    try:
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
        allowed_methods = [method for method in methods if requests.request(method, url).status_code < 400]
        return allowed_methods
    except requests.exceptions.RequestException:
        return ["[!] Error checking HTTP methods."]

def test_directory_traversal(url):
    """
    Tests for directory traversal vulnerabilities by injecting common traversal payloads
    into a query parameter named 'file'.
    """
    results = []
    traversal_payloads = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd"  # URL-encoded version
    ]
    for payload in traversal_payloads:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?file={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            # Basic check: /etc/passwd typically contains the string "root:"
            if "root:" in response.text.lower():
                results.append(f"[!] Directory Traversal vulnerability detected with payload: {payload}")
        except requests.exceptions.RequestException:
            continue
    if not results:
        results.append("[+] No directory traversal vulnerabilities detected.")
    return results

def network_scan(url, mode="basic"):
    results = []
    host = url.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Port scanning and banner grabbing
    open_ports = scan_open_ports(host)
    if open_ports:
        results.append(f"[+] Open Ports: {', '.join(map(str, open_ports))}")
        for port in open_ports:
            banner_result = grab_banner(host, port)
            results.append(banner_result)
    else:
        results.append("[!] No common open ports detected.")

    # HTTP methods check
    allowed_methods = get_http_methods(url)
    results.append(f"[+] Allowed HTTP Methods: {', '.join(allowed_methods)}")

    # If deep scan mode is selected, run directory traversal tests.
    if mode.lower() == "deep":
        results.extend(test_directory_traversal(url))

    return results
