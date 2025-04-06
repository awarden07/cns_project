from fpdf import FPDF
import os

REMEDIATION_MAPPING = {
    "SQL Injection": {
        "severity": "High",
        "recommendation": "Use parameterized queries and input validation."
    },
    "XSS": {
        "severity": "High",
        "recommendation": "Encode outputs and use Content Security Policy (CSP)."
    },
    "Heartbleed": {
        "severity": "Critical",
        "recommendation": "Upgrade OpenSSL to a non-vulnerable version."
    },
    "Weak Protocol": {
        "severity": "High",
        "recommendation": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; use TLS 1.2 or higher."
    },
    "No PFS": {
        "severity": "Medium",
        "recommendation": "Configure your server to use DHE or ECDHE cipher suites."
    },
    "Cookie": {
        "severity": "Medium",
        "recommendation": "Set Secure, HttpOnly, and SameSite attributes on cookies."
    },
    "Server Information Leakage": {
        "severity": "Low",
        "recommendation": "Configure your server to hide version info and sensitive headers."
    },
    "Directory Traversal": {
        "severity": "Critical",
        "recommendation": "Sanitize file path inputs and use whitelist-based validation."
    }
}

def map_vulnerability(issue_text):
    """Maps a vulnerability message to remediation recommendation."""
    lower_issue = issue_text.lower()
    for key in REMEDIATION_MAPPING:
        if key.lower() in lower_issue:
            return REMEDIATION_MAPPING[key]['recommendation']
    return "Review manually."

def generate_pdf_report(url, scan_results, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Web App Vulnerability Scan Report for {url}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "", 12)
    for result in scan_results:
        # Handle both old (string) and new (dict) format just in case
        if isinstance(result, dict):
            issue = result.get("issue", "Unknown issue")
            severity = result.get("severity", "Unknown")
        else:
            issue = str(result)
            severity = "Unknown"

        recommendation = map_vulnerability(issue)
        pdf.multi_cell(0, 10, f"Issue: {issue}\nSeverity: {severity}\nRemediation: {recommendation}\n")
        pdf.ln(2)

    # Ensure the reports directory exists
    os.makedirs("reports", exist_ok=True)
    final_filename = f"reports/{filename}"
    pdf.output(final_filename)
    return final_filename
