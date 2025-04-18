from flask import Flask, render_template, request, send_file
import threading
from modules.sqli_scanner import detect_sqli
from modules.xss_scanner import detect_reflected_xss, detect_stored_xss, detect_dom_xss
from modules.security_headers import check_security_headers
from modules.cookie_analyzer import analyze_cookies
from modules.ssl_tls_analyzer import check_ssl_tls
from modules.heartbleed_scanner import check_heartbleed
from modules.network_scanner import network_scan, test_directory_traversal 
from modules.report_generator import generate_pdf_report
import time
import urllib.parse

app = Flask(__name__)
latest_results = {}

def run_scanners(url, mode):
    """Run all scanners concurrently using threading for improved performance"""
    # Initialize categories
    categories = {
        "sql_injection": {"name": "SQL Injection Vulnerabilities", "results": []},
        "xss": {"name": "Cross-Site Scripting (XSS)", "results": []},
        "security_headers": {"name": "Security Header Analysis", "results": []},
        "ssl_tls": {"name": "SSL/TLS Configuration Analysis", "results": []},
        "network": {"name": "Network Security Analysis", "results": []}
    }
    
    # Create a lock for thread-safe operations
    results_lock = threading.Lock()
    
    # Define scanner functions for each module
    def run_sql_injection_scan():
        start_time = time.time()
        try:
            results = detect_sqli(url)
            with results_lock:
                categories["sql_injection"]["results"].extend(results)
                print(f"SQL Injection scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            with results_lock:
                categories["sql_injection"]["results"].append({"issue": f"SQL Injection scan failed: {e}", "severity": "Low"})
    
    def run_xss_scan():
        start_time = time.time()
        try:
            with results_lock:
                categories["xss"]["results"].extend(detect_reflected_xss(url))
                categories["xss"]["results"].extend(detect_stored_xss(url))
                categories["xss"]["results"].extend(detect_dom_xss(url))
                print(f"XSS scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            with results_lock:
                categories["xss"]["results"].append({"issue": f"XSS scan failed: {e}", "severity": "Low"})
    
    def run_security_headers_scan():
        start_time = time.time()
        try:
            with results_lock:
                categories["security_headers"]["results"].extend(check_security_headers(url))
                categories["security_headers"]["results"].extend(analyze_cookies(url))
                print(f"Security headers scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            with results_lock:
                categories["security_headers"]["results"].append({"issue": f"Security headers scan failed: {e}", "severity": "Low"})
    
    def run_ssl_tls_scan():
        start_time = time.time()
        try:
            with results_lock:
                categories["ssl_tls"]["results"].extend(check_ssl_tls(url))
            
            try:
                host = urllib.parse.urlparse(url).netloc
                with results_lock:
                    categories["ssl_tls"]["results"].extend(check_heartbleed(host))
            except Exception as e:
                with results_lock:
                    categories["ssl_tls"]["results"].append({"issue": f"Heartbleed scan failed: {e}", "severity": "Low"})
            
            print(f"SSL/TLS scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            with results_lock:
                categories["ssl_tls"]["results"].append({"issue": f"SSL/TLS scan failed: {e}", "severity": "Low"})
    
    def run_network_scan():
        start_time = time.time()
        try:
            with results_lock:
                categories["network"]["results"].extend(network_scan(url, mode))
            
            if mode.lower() == "deep":
                with results_lock:
                    categories["network"]["results"].extend(test_directory_traversal(url))
            
            print(f"Network scan completed in {time.time() - start_time:.2f} seconds")
        except Exception as e:
            with results_lock:
                categories["network"]["results"].append({"issue": f"Network scan failed: {e}", "severity": "Low"})
    
    # Create threads for each scan type
    threads = [
        threading.Thread(target=run_sql_injection_scan),
        threading.Thread(target=run_xss_scan),
        threading.Thread(target=run_security_headers_scan),
        threading.Thread(target=run_ssl_tls_scan),
        threading.Thread(target=run_network_scan)
    ]
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Combine all results for PDF report
    all_results = []
    for category in categories.values():
        all_results.extend(category["results"])
    
    return categories, all_results

def run_scanners(url, mode):
    """Run all scanners and organize results by category"""
    # Initialize categories
    categories = {
        "sql_injection": {"name": "SQL Injection Vulnerabilities", "results": []},
        "xss": {"name": "Cross-Site Scripting (XSS)", "results": []},
        "security_headers": {"name": "Security Header Analysis", "results": []},
        "ssl_tls": {"name": "SSL/TLS Configuration Analysis", "results": []},
        "network": {"name": "Network Security Analysis", "results": []}
    }
    
    # Run SQL Injection scans
    try:
        categories["sql_injection"]["results"].extend(detect_sqli(url))
    except Exception as e:
        categories["sql_injection"]["results"].append({"issue": f"SQL Injection scan failed: {e}", "severity": "Low"})
    
    # Run XSS scans
    try:
        categories["xss"]["results"].extend(detect_reflected_xss(url))
        categories["xss"]["results"].extend(detect_stored_xss(url))
        categories["xss"]["results"].extend(detect_dom_xss(url))
    except Exception as e:
        categories["xss"]["results"].append({"issue": f"XSS scan failed: {e}", "severity": "Low"})
    
    # Run Security Headers scans
    try:
        categories["security_headers"]["results"].extend(check_security_headers(url))
        categories["security_headers"]["results"].extend(analyze_cookies(url))
    except Exception as e:
        categories["security_headers"]["results"].append({"issue": f"Security headers scan failed: {e}", "severity": "Low"})
    
    # Run SSL/TLS scans
    try:
        categories["ssl_tls"]["results"].extend(check_ssl_tls(url))
        try:
            host = urllib.parse.urlparse(url).netloc
            categories["ssl_tls"]["results"].extend(check_heartbleed(host))
        except Exception as e:
            categories["ssl_tls"]["results"].append({"issue": f"Heartbleed scan failed: {e}", "severity": "Low"})
    except Exception as e:
        categories["ssl_tls"]["results"].append({"issue": f"SSL/TLS scan failed: {e}", "severity": "Low"})
    
    # Run Network scans
    try:
        categories["network"]["results"].extend(network_scan(url, mode))
        if mode.lower() == "deep":
            categories["network"]["results"].extend(test_directory_traversal(url))
    except Exception as e:
        categories["network"]["results"].append({"issue": f"Network scan failed: {e}", "severity": "Low"})
    
    # Combine all results for PDF report
    all_results = []
    for category in categories.values():
        all_results.extend(category["results"])
    
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
        
        # Run scans
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