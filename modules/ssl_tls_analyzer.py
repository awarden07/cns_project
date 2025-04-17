import ssl
import socket
import datetime
from urllib.parse import urlparse

def extract_hostname(url):
    """Extracts the hostname from a given URL."""
    parsed_url = urlparse(url)
    return parsed_url.hostname

def check_ssl_tls(url):
    """Checks SSL/TLS configurations for vulnerabilities with expanded checks."""
    results = []
    host = extract_hostname(url)

    try:
        # First check: Basic SSL/TLS configuration
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, 443))
        cert = conn.getpeercert()

        # Certificate Expiry Check
        expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        if expiry < datetime.datetime.utcnow():
            results.append({
                "issue": f"SSL Certificate Expired: {expiry}",
                "severity": "High"
            })
        else:
            days_remaining = (expiry - datetime.datetime.utcnow()).days
            if days_remaining < 30:
                results.append({
                    "issue": f"SSL Certificate expiring soon: {days_remaining} days remaining (expires {expiry})",
                    "severity": "Medium"
                })
            else:
                results.append({
                    "issue": f"SSL Certificate valid until: {expiry}",
                    "severity": "Low"
                })

        # Weak Cipher Check - expanded list
        weak_ciphers = ["RC4", "MD5", "SHA1", "DES", "3DES", "EXPORT"]
        for cipher in weak_ciphers:
            if cipher in str(conn.cipher()):
                results.append({
                    "issue": f"Weak Cipher Detected: {cipher}",
                    "severity": "High"
                })

        # SSL/TLS Version Check
        negotiated_protocol = conn.version()
        if negotiated_protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            results.append({
                "issue": f"Weak Protocol Detected: {negotiated_protocol}",
                "severity": "High"
            })
        else:
            results.append({
                "issue": f"Secure Protocol in use: {negotiated_protocol}",
                "severity": "Low"
            })

        # Check for certificate key strength
        if 'subjectPublicKey' in cert:
            key_length = len(cert['subjectPublicKey']) * 8  # Convert bytes to bits
            if key_length < 2048:
                results.append({
                    "issue": f"Weak certificate key length: {key_length} bits",
                    "severity": "High"
                })
            else:
                results.append({
                    "issue": f"Strong certificate key length: {key_length} bits",
                    "severity": "Low"
                })

        # Perfect Forward Secrecy (PFS) Check
        cipher_info = conn.cipher()
        cipher_name = cipher_info[0]
        
        # PFS detection logic
        if "DHE" in cipher_name or "ECDHE" in cipher_name:
            results.append({
                "issue": f"Perfect Forward Secrecy (PFS) is supported with cipher: {cipher_name}",
                "severity": "Low"
            })
        else:
            # Try explicitly with PFS ciphers
            try:
                pfs_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                pfs_context.set_ciphers('ECDHE:DHE')
                with pfs_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as s:
                    s.connect((host, 443))
                    pfs_cipher = s.cipher()[0]
                    results.append({
                        "issue": f"Perfect Forward Secrecy (PFS) is supported with cipher: {pfs_cipher}",
                        "severity": "Low"
                    })
            except:
                results.append({
                    "issue": f"No Perfect Forward Secrecy (PFS). Cipher used: {cipher_name}",
                    "severity": "Medium"
                })
        
        # OCSP Stapling check
        if 'OCSP' in cert.get('extensions', []):
            results.append({
                "issue": "OCSP Stapling is supported",
                "severity": "Low"
            })
        else:
            results.append({
                "issue": "OCSP Stapling not detected",
                "severity": "Medium"
            })

        conn.close()

    except Exception as e:
        results.append({
            "issue": f"Error testing SSL/TLS: {str(e)}",
            "severity": "Low"
        })

    return results