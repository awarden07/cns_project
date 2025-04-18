import requests
import json
import time
import datetime
import re
import urllib.parse
import base64

def analyze_cookies(url):
    """
    Analyzes HTTP cookies for security vulnerabilities with comprehensive detection.
    Checks for security flags, expiration, scope, size, and content patterns.
    """
    results = []

    try:
        session = requests.Session()
        response = session.get(url, timeout=5)
        cookies = session.cookies

        if not cookies:
            # Try a second request to ensure we get any JavaScript-set cookies
            session.get(url, timeout=5)
            cookies = session.cookies
            
        if not cookies:
            results.append({
                "issue": "No cookies detected in the application.",
                "severity": "Low"
            })
            return results

        # Cookie count check
        if len(cookies) > 30:
            results.append({
                "issue": f"Excessive number of cookies: {len(cookies)} (performance concern)",
                "severity": "Medium"
            })

        # Counter for potentially sensitive cookies
        sensitive_cookies_count = 0
        insecure_cookies_count = 0
        
        # Get current time for expiration checks
        now = datetime.datetime.now()

        # Analyze each cookie individually
        for cookie in cookies:
            cookie_name = cookie.name
            cookie_value = cookie.value
            cookie_issues = []
            cookie_strengths = []
            
            # Check if this appears to be a sensitive cookie
            sensitive_patterns = [
                r'sess', r'token', r'auth', r'login', r'pass', r'usr', r'uid', r'key', 
                r'secret', r'csrf', r'xsrf', r'id', r'sid'
            ]
            is_sensitive = any(re.search(pattern, cookie_name.lower()) for pattern in sensitive_patterns)
            if is_sensitive:
                sensitive_cookies_count += 1

            # Secure flag check
            if not cookie.secure:
                cookie_issues.append("Missing Secure flag")
                if is_sensitive:
                    insecure_cookies_count += 1
            else:
                cookie_strengths.append("Has Secure flag")

            # HttpOnly flag check
            if "httponly" not in str(cookie).lower():
                cookie_issues.append("Missing HttpOnly flag")
                if is_sensitive:
                    insecure_cookies_count += 1
            else:
                cookie_strengths.append("Has HttpOnly flag")

            # SameSite attribute check
            if "samesite" not in str(cookie).lower():
                cookie_issues.append("Missing SameSite attribute")
            else:
                samesite_value = None
                for item in str(cookie).split(';'):
                    if 'samesite' in item.lower():
                        samesite_value = item.split('=')[1].strip() if '=' in item else 'Lax'
                
                if samesite_value == 'None':
                    cookie_issues.append("SameSite=None (may allow cross-site requests)")
                else:
                    cookie_strengths.append(f"Has SameSite={samesite_value}")

            # Expiration check
            if not cookie.expires:
                cookie_issues.append("No expiration set (session cookie)")
            else:
                expiry_date = datetime.datetime.fromtimestamp(cookie.expires)
                days_valid = (expiry_date - now).days
                
                if days_valid > 365:
                    cookie_issues.append(f"Long expiration time ({days_valid} days)")
                    results.append({
                        "issue": f"Cookie '{cookie_name}' has excessive expiration: {days_valid} days",
                        "severity": "Medium"
                    })
                elif days_valid > 30 and is_sensitive:
                    cookie_issues.append(f"Sensitive cookie with long lifetime ({days_valid} days)")
                else:
                    cookie_strengths.append(f"Reasonable expiration time ({days_valid} days)")

            # Path check
            if cookie.path == "/" or not cookie.path:
                cookie_issues.append("Broad cookie scope (path=/)")
            else:
                cookie_strengths.append(f"Limited cookie scope (path={cookie.path})")

            # Size check
            cookie_size = len(str(cookie))
            if cookie_size > 4096:
                cookie_issues.append(f"Large cookie size ({cookie_size} bytes)")
                results.append({
                    "issue": f"Oversized cookie '{cookie_name}': {cookie_size} bytes (performance issue)",
                    "severity": "Medium"
                })

            # Check for common serialization formats (potential insecure deserialization)
            serialized_patterns = [
                (r'^[a-zA-Z0-9+/]{30,}={0,2}$', "base64 encoded"),
                (r'^{.*}$', "JSON data"),
                (r'^<.*>$', "XML data"),
                (r'O:[0-9]+:"', "PHP serialized object"),
                (r'^[a-zA-Z0-9%]+:[a-zA-Z0-9%]', "Serialized data")
            ]
            
            for pattern, format_name in serialized_patterns:
                if re.match(pattern, cookie_value):
                    if format_name == "base64 encoded":
                        try:
                            decoded = base64.b64decode(cookie_value + "=" * (-len(cookie_value) % 4)).decode('utf-8', errors='ignore')
                            if '{' in decoded and '}' in decoded:
                                cookie_issues.append(f"Contains encoded JSON data (potential deserialization issues)")
                            elif '<' in decoded and '>' in decoded:
                                cookie_issues.append(f"Contains encoded XML data (potential XXE issues)")
                        except:
                            pass
                    else:
                        cookie_issues.append(f"Contains {format_name} (potential deserialization issues)")
                    
                    if is_sensitive:
                        results.append({
                            "issue": f"Sensitive cookie '{cookie_name}' contains serialized data ({format_name})",
                            "severity": "Medium"
                        })
                    break

            # Check for weak cookie value patterns (predictable/sequential values)
            predictable_patterns = [
                (r'^[0-9]+$', "numeric ID"),
                (r'^[0-9a-f]{32}$', "MD5 hash"),
                (r'^[0-9a-f]{40}$', "SHA-1 hash")
            ]
            
            for pattern, value_type in predictable_patterns:
                if re.match(pattern, cookie_value) and is_sensitive:
                    if value_type == "numeric ID":
                        cookie_issues.append(f"Uses sequential numeric ID (predictable)")
                        results.append({
                            "issue": f"Sensitive cookie '{cookie_name}' uses predictable numeric identifier",
                            "severity": "Medium"
                        })
                    break

            # Determine severity based on issues and cookie sensitivity
            if cookie_issues:
                severity = "High" if is_sensitive and len(cookie_issues) >= 2 else \
                          "Medium" if is_sensitive or len(cookie_issues) >= 2 else "Low"
                
                issue_text = f"Cookie '{cookie_name}' has issues: " + ", ".join(cookie_issues)
                results.append({
                    "issue": issue_text,
                    "severity": severity
                })
            else:
                results.append({
                    "issue": f"Cookie '{cookie_name}' is secure: " + ", ".join(cookie_strengths),
                    "severity": "Low"
                })
        
        # Add summary findings
        if sensitive_cookies_count > 0:
            if insecure_cookies_count > 0:
                results.append({
                    "issue": f"Found {insecure_cookies_count} of {sensitive_cookies_count} sensitive cookies without proper security flags",
                    "severity": "High" if insecure_cookies_count > 1 else "Medium"
                })
            else:
                results.append({
                    "issue": f"All {sensitive_cookies_count} sensitive cookies have proper security flags",
                    "severity": "Low"
                })
        
        # Cross-site request forgery protection check
        csrf_patterns = [r'csrf', r'xsrf', r'token']
        has_csrf_protection = any(re.search(pattern, cookie_name.lower()) for cookie in cookies for pattern in csrf_patterns)
        
        if not has_csrf_protection:
            results.append({
                "issue": "No CSRF protection token detected in cookies",
                "severity": "Medium"
            })
        
        # Check response for Set-Cookie headers (could reveal more than cookies available in the request)
        set_cookie_headers = response.headers.getall('Set-Cookie') if hasattr(response.headers, 'getall') else response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else []
        if not set_cookie_headers and isinstance(response.headers, dict):
            set_cookie_headers = [v for k, v in response.headers.items() if k.lower() == 'set-cookie']
            
        # Analyze Set-Cookie headers for additional cookies or issues
        for header in set_cookie_headers:
            # Check for missing security flags in header
            if 'secure' not in header.lower():
                cookie_name = header.split('=')[0]
                results.append({
                    "issue": f"Cookie '{cookie_name}' set without Secure flag in header",
                    "severity": "Medium"
                })
                
            if 'httponly' not in header.lower():
                cookie_name = header.split('=')[0]
                results.append({
                    "issue": f"Cookie '{cookie_name}' set without HttpOnly flag in header",
                    "severity": "Medium"
                })

    except requests.exceptions.RequestException as e:
        results.append({
            "issue": f"Error analyzing cookies: {str(e)}",
            "severity": "Low"
        })

    return results