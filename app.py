from flask import Flask, render_template, request, send_file
import threading
import queue
import time
from modules.sqli_scanner import detect_sqli
from modules.xss_scanner import detect_reflected_xss, detect_stored_xss, detect_dom_xss
from modules.security_headers import check_security_headers
from modules.cookie_analyzer import analyze_cookies
from modules.ssl_tls_analyzer import check_ssl_tls
from modules.heartbleed_scanner import check_heartbleed
from modules.network_scanner import network_scan, test_directory_traversal 
from modules.report_generator import generate_pdf_report
import urllib.parse

app = Flask(__name__)
latest_results = {}

# Thread-safe container for scan results
class ScanResults:
    def __init__(self):
        self.categories = {
            "sql_injection": {"name": "SQL Injection Vulnerabilities", "results": []},
            "xss": {"name": "Cross-Site Scripting (XSS)", "results": []},
            "security_headers": {"name": "Security Header Analysis", "results": []},
            "ssl_tls": {"name": "SSL/TLS Configuration Analysis", "results": []},
            "network": {"name": "Network Security Analysis", "results": []}
        }
        self.lock = threading.Lock()
    
    def add_result(self, category, result):
        """Thread-safe way to add a result to a category"""
        with self.lock:
            self.categories[category]["results"].append(result)
    
    def add_results(self, category, results):
        """Thread-safe way to add multiple results to a category"""
        with self.lock:
            self.categories[category]["results"].extend(results)
    
    def get_all_results(self):
        """Returns all results across categories for report generation"""
        all_results = []
        with self.lock:
            for category in self.categories.values():
                all_results.extend(category["results"])
        return all_results
    
    def get_categories(self):
        """Returns the categories dictionary with results"""
        with self.lock:
            # Create a deep copy to avoid thread issues
            return {k: {"name": v["name"], "results": list(v["results"])} 
                   for k, v in self.categories.items()}

def run_scanners(url, mode):
    """Run all scanners concurrently using threading for improved performance"""
    # Initialize thread-safe result container
    scan_results = ScanResults()
    
    # Define scanner functions for each module
    def run_sql_injection_scan():
        start_time = time.time()
        try:
            results = detect_sqli(url)
            scan_results.add_results("sql_injection", results)
            print(f"SQL Injection scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            scan_results.add_result(
                "sql_injection", 
                {"issue": f"SQL Injection scan failed: {e}", "severity": "Low"}
            )
    
    def run_xss_scan():
        start_time = time.time()
        try:
            # Run reflected XSS scan
            reflect_results = detect_reflected_xss(url)
            scan_results.add_results("xss", reflect_results)
            
            # Run stored XSS scan
            stored_results = detect_stored_xss(url)
            scan_results.add_results("xss", stored_results)
            
            # Run DOM XSS scan
            dom_results = detect_dom_xss(url)
            scan_results.add_results("xss", dom_results)
            
            print(f"All XSS scans completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            scan_results.add_result(
                "xss", 
                {"issue": f"XSS scan failed: {e}", "severity": "Low"}
            )
    
    def run_security_headers_scan():
        start_time = time.time()
        try:
            # Check security headers
            headers_results = check_security_headers(url)
            scan_results.add_results("security_headers", headers_results)
            
            # Analyze cookies 
            cookie_results = analyze_cookies(url)
            scan_results.add_results("security_headers", cookie_results)
            
            print(f"Security headers scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            scan_results.add_result(
                "security_headers", 
                {"issue": f"Security headers scan failed: {e}", "severity": "Low"}
            )
    
    def run_ssl_tls_scan():
        start_time = time.time()
        try:
            # Check SSL/TLS configuration
            ssl_results = check_ssl_tls(url)
            scan_results.add_results("ssl_tls", ssl_results)
            
            # Check for Heartbleed vulnerability
            try:
                host = urllib.parse.urlparse(url).netloc
                heartbleed_results = check_heartbleed(host)
                scan_results.add_results("ssl_tls", heartbleed_results)
            except Exception as e:
                scan_results.add_result(
                    "ssl_tls", 
                    {"issue": f"Heartbleed scan failed: {e}", "severity": "Low"}
                )
            
            print(f"SSL/TLS scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            scan_results.add_result(
                "ssl_tls", 
                {"issue": f"SSL/TLS scan failed: {e}", "severity": "Low"}
            )
    
    def run_network_scan():
        start_time = time.time()
        try:
            # Basic network scan
            network_results = network_scan(url, mode)
            scan_results.add_results("network", network_results)
            
            # Run directory traversal tests if in deep scan mode
            if mode.lower() == "deep":
                dir_results = test_directory_traversal(url)
                scan_results.add_results("network", dir_results)
            
            print(f"Network scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            scan_results.add_result(
                "network", 
                {"issue": f"Network scan failed: {e}", "severity": "Low"}
            )
    
    # Create all scanner threads
    scanner_threads = [
        threading.Thread(target=run_sql_injection_scan),
        threading.Thread(target=run_xss_scan),
        threading.Thread(target=run_security_headers_scan),
        threading.Thread(target=run_ssl_tls_scan),
        threading.Thread(target=run_network_scan)
    ]
    
    # Start all scanner threads
    for thread in scanner_threads:
        thread.start()
    
    # Wait for all threads to complete
    for thread in scanner_threads:
        thread.join()
    
    # Return categories and all results
    categories = scan_results.get_categories()
    all_results = scan_results.get_all_results()
    
    return categories, all_results

@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results
    categories = {}
    all_results = []
    url = ""
    scan_mode = "basic"
    scan_time = None

    if request.method == "POST":
        url = request.form["url"].strip()
        scan_mode = request.form.get("mode", "basic")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        # Record scan start time
        start_time = time.time()
        
        # Run concurrent scans
        categories, all_results = run_scanners(url, scan_mode)
        
        # Calculate scan duration
        scan_time = round(time.time() - start_time, 2)
        
        # Store results for PDF generation
        latest_results = {
            "url": url, 
            "results": all_results, 
            "mode": scan_mode,
            "scan_time": scan_time
        }

    return render_template(
        "index.html", 
        url=url, 
        categories=categories, 
        scan_time=scan_time,
        mode=scan_mode
    )

@app.route("/download_report")
def download_report():
    global latest_results
    if latest_results:
        filename = generate_pdf_report(
            latest_results["url"], 
            latest_results["results"],
            f"scan_report_{urllib.parse.quote(latest_results['url'], safe='')}.pdf"
        )
        return send_file(filename, as_attachment=True)
    return "No scan results available.", 404

if __name__ == "__main__":
    app.run(debug=True)