import ssl
import socket
import datetime
from urllib.parse import urlparse

def extract_hostname(url):
    """Extracts the hostname from a given URL."""
    parsed_url = urlparse(url)
    return parsed_url.hostname

def check_ssl_tls(url):
    """Checks SSL/TLS configurations for vulnerabilities."""
    results = []
    host = extract_hostname(url)  # Extract the correct hostname

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.connect((host, 443))
        cert = conn.getpeercert()

        expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        if expiry < datetime.datetime.utcnow():
            results.append(f"[!] SSL Certificate Expired: {expiry}")

        weak_ciphers = ["RC4", "MD5", "SHA1"]
        for cipher in weak_ciphers:
            if cipher in str(cert):
                results.append(f"[!] Weak Cipher Detected: {cipher}")

    except Exception as e:
        results.append(f"[!] Error testing SSL/TLS: {str(e)}")

    return results
