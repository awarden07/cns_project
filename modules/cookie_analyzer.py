import requests
import json
import time

def analyze_cookies(url):
    """Analyzes HTTP cookies for security vulnerabilities with enhanced detection."""
    results = []

    try:
        session = requests.Session()
        response = session.get(url, timeout=5)
        cookies = response.cookies

        if not cookies:
            results.append({
                "issue": "No cookies detected.",
                "severity": "Low"
            })
            return results

        for cookie in cookies:
            cookie_name = cookie.name
            cookie_issues = []
            cookie_strengths = []

            # Secure flag check
            if not cookie.secure:
                cookie_issues.append("Missing Secure flag")
            else:
                cookie_strengths.append("Has Secure flag")

            # HttpOnly flag check
            if "httponly" not in str(cookie).lower():
                cookie_issues.append("Missing HttpOnly flag")
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
                cookie_issues.append("No expiration set")
            else:
                expiry_date = datetime.datetime.fromtimestamp(cookie.expires)
                now = datetime.datetime.now()
                days_valid = (expiry_date - now).days
                
                if days_valid > 365:
                    cookie_issues.append(f"Long expiration time ({days_valid} days)")
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

            # Check for session identifiers in cookie names
            session_id_names = ['sessid', 'session', 'id', 'sid', 'auth', 'token']
            if any(sid_name in cookie_name.lower() for sid_name in session_id_names):
                if not cookie.secure or "httponly" not in str(cookie).lower():
                    cookie_issues.append("Potentially sensitive cookie missing security flags")

            # Determine severity based on issues
            if cookie_issues:
                severity = "High" if len(cookie_issues) >= 3 else "Medium" if len(cookie_issues) >= 1 else "Low"
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

        # Additional check: too many cookies?
        if len(cookies) > 30:
            results.append({
                "issue": f"Excessive number of cookies: {len(cookies)} (performance concern)",
                "severity": "Medium"
            })

    except requests.exceptions.RequestException as e:
        results.append({
            "issue": f"Error analyzing cookies: {str(e)}",
            "severity": "Low"
        })

    return results