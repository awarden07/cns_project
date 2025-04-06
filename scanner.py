from modules.sqli_scanner import detect_sqli
from modules.xss_scanner import detect_reflected_xss, detect_stored_xss, detect_dom_xss
from modules.security_headers import check_security_headers
from modules.ssl_tls_analyzer import check_ssl_tls
from modules.network_scanner import network_scan
from modules.report_generator import generate_pdf_report
from modules.cookie_analyzer import analyze_cookies
from modules.heartbleed_scanner import check_heartbleed
from modules.directory_traversal import test_directory_traversal

def run_full_scan(url):
    """Runs all security scans on the given URL."""
    print(f"\n[+] Scanning {url}...\n")
    results = []
    results.extend(detect_sqli(url))
    results.extend(detect_reflected_xss(url))
    results.extend(detect_stored_xss(url))
    results.extend(detect_dom_xss(url))
    results.extend(check_security_headers(url))
    results.extend(analyze_cookies(url))
    results.extend(check_ssl_tls(url))
    results.extend(check_heartbleed(url))
    results.extend(network_scan(url))
    results.extend(test_directory_traversal(url))

    for result in results:
        print(result)

    report_name = generate_pdf_report(results, "scan_report.pdf")
    print(f"\n[+] Scan completed. Report saved as: {report_name}")

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    run_full_scan(target_url)
