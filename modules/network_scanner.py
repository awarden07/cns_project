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
            return {
                "issue": f"Banner for {host}:{port} -> {banner}",
                "severity": "Low"
            }
        else:
            return {
                "issue": f"No banner detected for {host}:{port}",
                "severity": "Low"
            }
    except Exception:
        return {
            "issue": f"Unable to grab banner for {host}:{port}",
            "severity": "Low"
        }

def get_http_methods(url):
    try:
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
        allowed_methods = []
        for method in methods:
            try:
                response = requests.request(method, url)
                if response.status_code < 400:
                    allowed_methods.append(method)
            except Exception:
                continue
        return allowed_methods
    except requests.exceptions.RequestException:
        return []

def test_directory_traversal(url):
    results = []
    payloads = [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd"
    ]
    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?file={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            if "root:" in response.text.lower():
                results.append({
                    "issue": f"Directory Traversal detected with payload: {payload}",
                    "severity": "High"
                })
        except requests.exceptions.RequestException:
            continue

    if not results:
        results.append({
            "issue": "No directory traversal vulnerabilities detected.",
            "severity": "Low"
        })
    return results

def network_scan(url, mode="basic"):
    results = []
    host = url.replace("http://", "").replace("https://", "").split("/")[0]

    # Port scan
    open_ports = scan_open_ports(host)
    if open_ports:
        results.append({
            "issue": f"Open Ports: {', '.join(map(str, open_ports))}",
            "severity": "Medium"
        })
        for port in open_ports:
            results.append(grab_banner(host, port))
    else:
        results.append({
            "issue": "No common open ports detected.",
            "severity": "Low"
        })

    # HTTP methods
    methods = get_http_methods(url)
    if methods:
        severity = "Medium" if set(methods) & {"PUT", "DELETE", "PATCH"} else "Low"
        results.append({
            "issue": f"Allowed HTTP Methods: {', '.join(methods)}",
            "severity": severity
        })
    else:
        results.append({
            "issue": "Could not determine allowed HTTP methods.",
            "severity": "Low"
        })

    return results
