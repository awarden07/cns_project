from flask import Flask, render_template, request, send_file
import threading
from modules.sqli_scanner import detect_sqli
from modules.xss_scanner import detect_reflected_xss, detect_stored_xss, detect_dom_xss
from modules.security_headers import check_security_headers
from modules.cookie_analyzer import analyze_cookies
from modules.ssl_tls_analyzer import check_ssl_tls
from modules.heartbleed_scanner import check_heartbleed
from modules.network_scanner import scan_open_ports
from modules.report_generator import generate_pdf_report

app = Flask(__name__)

# Store the latest scan results globally for report generation
latest_results = {}

def run_scanners(url, results):
    """Runs all security checks in parallel."""
    threads = [
        threading.Thread(target=lambda: results.extend(detect_sqli(url))),
        threading.Thread(target=lambda: results.extend(detect_reflected_xss(url))),
        threading.Thread(target=lambda: results.extend(detect_stored_xss(url))),
        threading.Thread(target=lambda: results.extend(detect_dom_xss(url))),
        threading.Thread(target=lambda: results.extend(check_security_headers(url))),
        threading.Thread(target=lambda: results.extend(analyze_cookies(url))),
        threading.Thread(target=lambda: results.extend(check_ssl_tls(url))),
        threading.Thread(target=lambda: results.extend(check_heartbleed(url))),
        threading.Thread(target=lambda: results.extend(scan_open_ports(url)))
    ]
    
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results
    results = []

    if request.method == "POST":
        url = request.form["url"].strip()

        if not url.startswith("http"):
            url = "http://" + url  # Ensure valid URL format

        # Store results in a thread-safe way
        latest_results = {"url": url, "results": results}

        # Run scanners in parallel
        run_scanners(url, results)

    return render_template("index.html", url=latest_results.get("url"), results=latest_results.get("results"))

@app.route("/download_report")
def download_report():
    global latest_results
    if latest_results:
        filename = generate_pdf_report(latest_results["url"], latest_results["results"])
        return send_file(filename, as_attachment=True)
    return "No scan results available.", 404

if __name__ == "__main__":
    app.run(debug=True)
