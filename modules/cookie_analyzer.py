import requests

def analyze_cookies(url):
    """Analyzes HTTP cookies for security vulnerabilities."""
    results = []
    
    try:
        session = requests.Session()
        response = session.get(url, timeout=5)
        cookies = response.cookies

        if not cookies:
            results.append("[+] No cookies detected.")
            return results

        for cookie in cookies:
            cookie_name = cookie.name
            cookie_issues = []

            # Secure flag check
            if not cookie.secure:
                cookie_issues.append("[!] Missing Secure flag (should only be transmitted over HTTPS)")

            # HttpOnly flag check
            if "HttpOnly" not in cookie._rest:
                cookie_issues.append("[!] Missing HttpOnly flag (vulnerable to XSS)")

            # SameSite attribute check
            if "SameSite" not in cookie._rest:
                cookie_issues.append("[!] Missing SameSite attribute (vulnerable to CSRF)")

            # Expiration check
            if not cookie.expires:
                cookie_issues.append("[!] No expiration set (session persists indefinitely)")

            # Format output
            results.append(f"[+] Cookie `{cookie_name}` Analysis: " + " ".join(cookie_issues) if cookie_issues else f"[+] Cookie `{cookie_name}` is secure.")

    except requests.exceptions.RequestException as e:
        results.append(f"[!] Error analyzing cookies: {str(e)}")

    return results
