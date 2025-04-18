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

# JavaScript sinks that can lead to DOM XSS
DOM_SINKS = {
    "immediate": [
        "document.write", 
        "innerHTML", 
        "outerHTML", 
        "insertAdjacentHTML", 
        "document.writeln",
        "iframe.src"
    ],
    "execution": [
        "eval", 
        "Function", 
        "setTimeout", 
        "setInterval",
        "execScript"
    ],
    "url": [
        "location", 
        "location.href", 
        "location.replace", 
        "location.assign",
        "window.open", 
        "document.URL", 
        "document.documentURI",
        "document.referrer"
    ]
}

# JavaScript sources that can feed into DOM XSS
DOM_SOURCES = [
    "location", 
    "location.href", 
    "location.search", 
    "location.hash", 
    "location.pathname",
    "document.URL", 
    "document.documentURI", 
    "document.referrer",
    "window.name", 
    "document.cookie",
    "localStorage", 
    "sessionStorage",
    "history.pushState", 
    "history.replaceState",
    "postMessage", 
    "addEventListener",
    "XMLHttpRequest"
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

def extract_js_content(html_content):
    """Extracts JavaScript content from HTML."""
    # Extract script tag contents
    script_content = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL)
    
    # Extract inline event handlers
    inline_handlers = re.findall(r'on\w+\s*=\s*["\']([^"\']+)["\']', html_content)
    
    # Extract JS URLs
    js_urls = re.findall(r'(?:href|src)\s*=\s*["\']javascript:([^"\']+)["\']', html_content)
    
    # Combine all JavaScript content
    all_js = ' '.join(script_content + inline_handlers + js_urls)
    
    return all_js

def analyze_js_execution_patterns(js_content):
    """Analyzes JavaScript execution patterns to detect DOM XSS vulnerabilities."""
    issues = []
    
    # Check for sink usage
    for category, sinks in DOM_SINKS.items():
        for sink in sinks:
            if sink in js_content:
                # Check for direct link between sources and sinks
                for source in DOM_SOURCES:
                    # Look for patterns indicating source data is being passed to sink
                    source_to_sink = re.search(rf'{sink}\s*\([^)]*{source}', js_content) or \
                                    re.search(rf'{sink}\s*=\s*[^;]*{source}', js_content)
                    
                    if source_to_sink:
                        issues.append({
                            "issue": f"High-risk DOM XSS flow detected: {source} → {sink}",
                            "severity": "High"
                        })
                    elif source in js_content:
                        # Potential but indirect flow
                        issues.append({
                            "issue": f"Potential DOM XSS: Both {source} (source) and {sink} (sink) found in JavaScript",
                            "severity": "Medium"
                        })
    
    # Check for common vulnerable patterns
    vulnerable_patterns = [
        (r'document\.write\s*\(\s*.*?location', "document.write with location input"),
        (r'innerHTML\s*=\s*.*?location', "innerHTML with location input"),
        (r'eval\s*\(\s*.*?document\.URL', "eval with document.URL"),
        (r'setTimeout\s*\(\s*.*?location', "setTimeout with location input"),
        (r'document\.write\s*\(\s*.*?document\.referrer', "document.write with document.referrer input"),
        (r'\.innerHTML\s*=\s*.*?\$_GET', "innerHTML with $_GET (URL parameter)"),
        (r'\.innerHTML\s*=\s*.*?\$_REQUEST', "innerHTML with $_REQUEST input"),
        (r'location\s*=\s*.*?user', "location assignment with user-controlled input"),
        (r'href\s*=\s*.*?hash', "href assignment from URL hash")
    ]
    
    for pattern, description in vulnerable_patterns:
        if re.search(pattern, js_content, re.IGNORECASE | re.DOTALL):
            issues.append({
                "issue": f"DOM XSS vulnerable pattern found: {description}",
                "severity": "High"
            })
    
    return issues

def detect_dom_xss(url):
    results = []
    
    try:
        # First, get the page content
        response = requests.get(url, timeout=10)
        page_content = response.text
        
        # Extract all JavaScript content
        js_content = extract_js_content(page_content)
        
        # Analyze JavaScript for vulnerable patterns
        js_issues = analyze_js_execution_patterns(js_content)
        results.extend(js_issues)
        
        # Check response of pages with specific payloads
        for payload in XSS_PAYLOADS[:5]:  # Limit to first 5 payloads for performance
            encoded_payload = urllib.parse.quote(payload)
            
            # Test parameters that commonly lead to DOM XSS
            for param in ["id", "search", "query", "q", "s", "hash", "value", "name", "input"]:
                test_url = f"{url}?{param}={encoded_payload}"
                try:
                    test_response = requests.get(test_url, timeout=5)
                    test_content = test_response.text
                    
                    # Check if the payload appears unmodified in the response
                    # This is a very basic check and doesn't guarantee actual vulnerability
                    if payload in test_content:
                        # Further check if it appears in a script context
                        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', test_content, re.DOTALL)
                        for script in script_tags:
                            if payload in script:
                                results.append({
                                    "issue": f"Potential DOM XSS vulnerability detected with parameter '{param}'",
                                    "severity": "High"
                                })
                                break
                except requests.exceptions.RequestException:
                    continue
        
        # Check for vulnerable JavaScript libraries
        vulnerable_libraries = [
            (r'jquery-1\.[0-9]\.[0-9]', "jQuery 1.x (multiple XSS vulnerabilities)"),
            (r'jquery-2\.[0-9]\.[0-9]', "jQuery 2.x (potential XSS vulnerabilities)"),
            (r'angular\.js/1\.[2-4]', "AngularJS 1.2-1.4 (multiple XSS issues)"),
            (r'prototype-1\.[0-6]', "Prototype.js <= 1.6 (XSS vulnerabilities)"),
            (r'dojo/1\.[0-9]\.[0-9]', "Dojo Toolkit (check version for XSS issues)")
        ]
        
        for lib_pattern, lib_description in vulnerable_libraries:
            if re.search(lib_pattern, page_content):
                results.append({
                    "issue": f"Potentially vulnerable JavaScript library detected: {lib_description}",
                    "severity": "Medium"
                })
        
        # If no issues found, add a low severity note
        if not results:
            results.append({
                "issue": "No DOM-Based XSS vulnerabilities detected.",
                "severity": "Low"
            })
            
    except requests.exceptions.RequestException as e:
        results.append({
            "issue": f"Error analyzing DOM XSS: {str(e)}",
            "severity": "Low"
        })
        
    return results