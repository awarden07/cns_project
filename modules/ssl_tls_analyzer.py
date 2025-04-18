import ssl
import socket
import datetime
import urllib.parse

def extract_hostname(url):
    """Extracts the hostname from a given URL."""
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.hostname

def check_pfs_support(host, port=443):
    """Check for Perfect Forward Secrecy support."""
    results = []
    pfs_detected = False
    pfs_cipher = None
    
    try:
        # Try connecting with explicit PFS cipher preference
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        try:
            # Try to set PFS ciphers only
            context.set_ciphers('ECDHE:DHE')
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cipher = s.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    if 'DHE' in cipher_name or 'ECDHE' in cipher_name:
                        pfs_detected = True
                        pfs_cipher = cipher_name
        except (ssl.SSLError, socket.error):
            # The explicit cipher preference might fail, try default context
            pass
            
        if not pfs_detected:
            # Try with default context
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cipher = s.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    if 'DHE' in cipher_name or 'ECDHE' in cipher_name:
                        pfs_detected = True
                        pfs_cipher = cipher_name
        
        # Try individual ciphers to get a more complete picture
        if not pfs_detected:
            test_ciphers = [
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'DHE-RSA-AES256-GCM-SHA384',
                'DHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES128-GCM-SHA256'
            ]
            
            for cipher_suite in test_ciphers:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.set_ciphers(cipher_suite)
                    with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as s:
                        s.settimeout(5)
                        s.connect((host, port))
                        actual_cipher = s.cipher()[0]
                        if 'ECDHE' in actual_cipher or 'DHE' in actual_cipher:
                            pfs_detected = True
                            pfs_cipher = actual_cipher
                            break
                except (ssl.SSLError, socket.error):
                    continue
        
        # Generate results based on findings
        if pfs_detected:
            cipher_details = f" using cipher: {pfs_cipher}" if pfs_cipher else ""
            key_exchange = "ECDHE" if pfs_cipher and "ECDHE" in pfs_cipher else "DHE" if pfs_cipher and "DHE" in pfs_cipher else "Unknown"
            cipher_strength = "strong" if pfs_cipher and ("GCM" in pfs_cipher or "POLY1305" in pfs_cipher) else "acceptable"
            
            results.append({
                "issue": f"Perfect Forward Secrecy (PFS) is supported with {key_exchange} key exchange{cipher_details}",
                "severity": "Low"
            })
            
            if cipher_strength == "strong":
                results.append({
                    "issue": "Server prioritizes modern AEAD ciphers with PFS (excellent security)",
                    "severity": "Low"
                })
        else:
            results.append({
                "issue": "Perfect Forward Secrecy (PFS) is NOT supported. Server does not prioritize ECDHE or DHE cipher suites.",
                "severity": "High"
            })
    
    except Exception as e:
        results.append({
            "issue": f"Error testing Perfect Forward Secrecy: {str(e)}",
            "severity": "Low"
        })
    
    return results

def check_ssl_tls(url):
    """Enhanced SSL/TLS analysis with improved PFS verification."""
    results = []
    host = extract_hostname(url)
    
    try:
        # Basic SSL/TLS checks
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, 443))
        
        # Get certificate details
        cert = conn.getpeercert()
        protocol = conn.version()
        cipher = conn.cipher()
        
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
        
        # Protocol version check
        if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            results.append({
                "issue": f"Weak Protocol Detected: {protocol}",
                "severity": "High"
            })
        else:
            results.append({
                "issue": f"Secure Protocol in use: {protocol}",
                "severity": "Low"
            })
            
        # Cipher check
        weak_ciphers = ["RC4", "MD5", "SHA1", "DES", "3DES", "EXPORT", "NULL"]
        for weak in weak_ciphers:
            if weak in str(cipher):
                results.append({
                    "issue": f"Weak Cipher Detected: {weak}",
                    "severity": "High"
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
        
        # Close connection
        conn.close()
        
        # Check for Perfect Forward Secrecy
        pfs_results = check_pfs_support(host)
        results.extend(pfs_results)
        
    except Exception as e:
        results.append({
            "issue": f"Error testing SSL/TLS: {str(e)}",
            "severity": "Low"
        })
    
    return results