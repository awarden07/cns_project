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
    host = extract_hostname(url)
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        
        # Certificate Expiry Check
        expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        if expiry < datetime.datetime.utcnow():
            results.append(f"[!] SSL Certificate Expired: {expiry}")
        else:
            results.append(f"[+] SSL Certificate valid until: {expiry}")

        # Weak Cipher Check
        weak_ciphers = ["RC4", "MD5", "SHA1"]
        for cipher in weak_ciphers:
            if cipher in str(cert):
                results.append(f"[!] Weak Cipher Detected: {cipher}")

        # SSL/TLS Version Check
        negotiated_protocol = conn.version()
        if negotiated_protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            results.append(f"[!] Weak Protocol Detected: {negotiated_protocol}")
        else:
            results.append(f"[+] Secure Protocol in use: {negotiated_protocol}")

        # Perfect Forward Secrecy (PFS) Check
        cipher_info = conn.cipher()  # returns (cipher_name, protocol_version, key_exchange_algo)
        cipher_name = cipher_info[0]
        if "DHE" in cipher_name or "ECDHE" in cipher_name:
            results.append(f"[+] Perfect Forward Secrecy (PFS) is supported with cipher: {cipher_name}")
        else:
            results.append(f"[!] No Perfect Forward Secrecy (PFS). Cipher used: {cipher_name}")
        
        conn.close()

    except Exception as e:
        results.append(f"[!] Error testing SSL/TLS: {str(e)}")

    return results
