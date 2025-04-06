from fpdf import FPDF

# Example mapping for vulnerability severity and remediation recommendations
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

def map_vulnerability(result):
    """Maps a vulnerability message to severity and remediation recommendation."""
    lower_result = result.lower()
    for key in REMEDIATION_MAPPING:
        if key.lower() in lower_result:
            mapping = REMEDIATION_MAPPING[key]
            return f"Severity: {mapping['severity']}. Remediation: {mapping['recommendation']}"
    return "Severity: Unknown. Remediation: Review manually."

def generate_pdf_report(url, scan_results, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Web App Vulnerability Scan Report for {url}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "", 12)
    for result in scan_results:
        remediation = map_vulnerability(result)
        pdf.multi_cell(0, 10, f"{result}\n{remediation}\n")
        pdf.ln(2)

    # Save report to the "report" folder
    final_filename = f"reports/{filename}"
    pdf.output(final_filename)
    return final_filename
