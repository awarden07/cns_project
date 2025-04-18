import socket
import requests
import urllib.parse
import re
import time

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
    """
    Tests for directory traversal vulnerabilities by trying various payloads
    on common parameters and checking responses for file content signatures.
    """
    results = []
    # Common parameters that might be vulnerable to directory traversal
    parameters = [
        "file", "document", "folder", "path", "style", "template", 
        "filepath", "directory", "load", "doc", "page", "filename", 
        "download", "view", "include", "require", "read"
    ]
    
    # Common directory traversal payloads
    payloads = [
        "../../../../etc/passwd",  # Standard path traversal
        "../../../etc/passwd",     # Fewer levels
        "../../etc/passwd",        # Even fewer levels
        "../../../../etc/passwd%00",  # Null byte injection for bypassing extensions
        "..\\..\\..\\..\\Windows\\win.ini",  # Windows path traversal
        "..%252f..%252f..%252fetc/passwd",  # Double URL encoding bypass
        "/etc/passwd",  # Direct path (some applications may not require traversal)
        "....//....//....//etc/passwd"  # Filter evasion technique
    ]
    
    # Patterns that indicate a successful directory traversal
    passwd_patterns = [
        r"root:.*:0:0:",
        r"bin:.*:/bin",
        r"daemon:.*:/usr/sbin",
        r"nobody:.*/nonexistent"
    ]
    
    windows_patterns = [
        r"\[fonts\]",
        r"\[extensions\]",
        r"for 16-bit app support"
    ]
    
    # Track which parameters we've already found to be vulnerable
    vulnerable_params = set()
    
    # Test each parameter with each payload
    for param in parameters:
        # Skip if we already found this parameter to be vulnerable
        if param in vulnerable_params:
            continue
            
        for payload in payloads:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"
            
            try:
                response = requests.get(test_url, timeout=10)
                response_text = response.text.lower()
                
                # Check if response contains any of the pattern indicators
                is_vulnerable = False
                
                # Check for Unix/Linux passwd file patterns
                if "etc/passwd" in payload.lower():
                    for pattern in passwd_patterns:
                        if re.search(pattern, response_text):
                            is_vulnerable = True
                            break
                
                # Check for Windows file patterns
                elif "windows" in payload.lower() or "win.ini" in payload.lower():
                    for pattern in windows_patterns:
                        if re.search(pattern, response_text):
                            is_vulnerable = True
                            break
                
                # If pattern is found, mark as vulnerable
                if is_vulnerable:
                    results.append({
                        "issue": f"Directory Traversal vulnerability detected via parameter '{param}' with payload: {payload}",
                        "severity": "High"
                    })
                    vulnerable_params.add(param)
                    break  # No need to try more payloads for this parameter
                    
            except requests.exceptions.RequestException:
                continue  # Skip to next payload if request fails

    # If no vulnerabilities found, report that
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
        dangerous_methods = set(["PUT", "DELETE", "PATCH"])
        severity = "High" if dangerous_methods.intersection(set(methods)) else "Medium" if "OPTIONS" in methods else "Low"
        results.append({
            "issue": f"Allowed HTTP Methods: {', '.join(methods)}",
            "severity": severity
        })
    else:
        results.append({
            "issue": "Could not determine allowed HTTP methods.",
            "severity": "Low"
        })

    # Directory traversal if deep mode
    if mode.lower() == "deep":
        results.extend(test_directory_traversal(url))

    return results
