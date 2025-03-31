from modules.sqli_scanner import test_sql_injection
from modules.xss_scanner import test_xss
from modules.security_headers import check_security_headers
from modules.ssl_tls_analyzer import check_ssl_tls
from modules.network_scanner import network_scan
from modules.report_generator import generate_pdf_report

def run_full_scan(url):
    """Runs all security scans on the given URL."""
    print(f"\n[+] Scanning {url}...\n")

    results = []
    results.extend(test_sql_injection(url))
    results.extend(test_xss(url))
    results.extend(check_security_headers(url))
    results.extend(check_ssl_tls(url))
    results.extend(network_scan(url))

    # Print results
    for result in results:
        print(result)

    # Generate a PDF report
    report_name = generate_pdf_report(results, "scan_report.pdf")
    print(f"\n[+] Scan completed. Report saved as: {report_name}")

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    run_full_scan(target_url)
