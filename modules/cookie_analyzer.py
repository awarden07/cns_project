import requests

def analyze_cookies(url):
    """Analyzes HTTP cookies for security vulnerabilities."""
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

            # Secure flag check
            if not cookie.secure:
                cookie_issues.append("Missing Secure flag")

            # HttpOnly flag check
            if "HttpOnly" not in cookie._rest:
                cookie_issues.append("Missing HttpOnly flag")

            # SameSite attribute check
            if "SameSite" not in cookie._rest:
                cookie_issues.append("Missing SameSite attribute")

            # Expiration check
            if not cookie.expires:
                cookie_issues.append("No expiration set")

            if cookie_issues:
                results.append({
                    "issue": f"Cookie '{cookie_name}' has issues: " + ", ".join(cookie_issues),
                    "severity": "Medium" if len(cookie_issues) <= 2 else "High"
                })
            else:
                results.append({
                    "issue": f"Cookie '{cookie_name}' is secure.",
                    "severity": "Low"
                })

    except requests.exceptions.RequestException as e:
        results.append({
            "issue": f"Error analyzing cookies: {str(e)}",
            "severity": "Low"
        })

    return results
