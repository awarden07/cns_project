from fpdf import FPDF
import os
import time
import datetime

# Comprehensive remediation mapping
REMEDIATION_MAPPING = {
    "SQL Injection": {
        "severity": "High",
        "recommendation": "Use parameterized queries and prepared statements. Implement input validation, escaping, and ORM frameworks. Apply the principle of least privilege for database accounts."
    },
    "Reflected XSS": {
        "severity": "High",
        "recommendation": "Implement output encoding specific to the context (HTML, JavaScript, CSS, URL). Use Content Security Policy (CSP) headers. Sanitize all user inputs and validate against whitelist."
    },
    "Stored XSS": {
        "severity": "High", 
        "recommendation": "Sanitize user input before storing in the database. Implement context-specific output encoding when displaying stored data. Use CSP headers and consider using HTML Sanitizer libraries."
    },
    "DOM XSS": {
        "severity": "High",
        "recommendation": "Avoid using vulnerable JavaScript methods like innerHTML, document.write. Use safe DOM methods like textContent instead. Sanitize data before using it in JavaScript contexts."
    },
    "Heartbleed": {
        "severity": "Critical",
        "recommendation": "Upgrade OpenSSL to a non-vulnerable version (1.0.1g or later). Generate new SSL certificates and keys. Revoke and replace compromised certificates."
    },
    "Weak Protocol": {
        "severity": "High",
        "recommendation": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; Configure server to only use TLS 1.2 or higher. Update client requirements to support modern protocols."
    },
    "Weak Cipher": {
        "severity": "High",
        "recommendation": "Configure server to only use strong ciphers (AES-GCM, ChaCha20). Disable weak ciphers (RC4, DES, 3DES). Prioritize AEAD cipher suites and use proper cipher ordering."
    },
    "No PFS": {
        "severity": "Medium",
        "recommendation": "Configure your server to use DHE or ECDHE cipher suites for Perfect Forward Secrecy. Ensure DH key size is at least 2048 bits. Prioritize ECDHE over DHE for better performance."
    },
    "Cookie": {
        "severity": "Medium",
        "recommendation": "Set Secure, HttpOnly, and SameSite=Strict attributes for sensitive cookies. Implement proper cookie expiration. Use CSRF tokens for sensitive operations. Limit cookie scope with Path attribute."
    },
    "Missing Security Header": {
        "severity": "Medium",
        "recommendation": "Implement all recommended security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy."
    },
    "Server Information Leakage": {
        "severity": "Low",
        "recommendation": "Configure your server to hide version info in headers. Remove unnecessary headers that reveal technology information. Use generic error pages in production."
    },
    "Directory Traversal": {
        "severity": "Critical",
        "recommendation": "Sanitize file path inputs and use whitelist-based validation. Implement proper authorization checks. Use secure file handling APIs and avoid passing user input directly to file operations."
    },
    "Insecure HTTP Method": {
        "severity": "Medium",
        "recommendation": "Disable unnecessary HTTP methods (PUT, DELETE, TRACE) if not required. Implement proper authentication and authorization for dangerous methods. Use method restrictions in web server configuration."
    },
    "CSRF Vulnerability": {
        "severity": "Medium",
        "recommendation": "Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Validate the Origin and Referer headers for sensitive requests."
    },
    "SSL Certificate Issue": {
        "severity": "Medium",
        "recommendation": "Ensure certificates are valid and not expired. Use certificates from trusted CAs. Implement proper certificate chain. Configure OCSP stapling and certificate transparency."
    }
}

def map_vulnerability(issue_text):
    """Maps a vulnerability message to specific remediation recommendations."""
    lower_issue = issue_text.lower()
    
    # Match vulnerability types
    if "sql injection" in lower_issue:
        return REMEDIATION_MAPPING["SQL Injection"]
    elif "reflected xss" in lower_issue:
        return REMEDIATION_MAPPING["Reflected XSS"]
    elif "stored xss" in lower_issue:
        return REMEDIATION_MAPPING["Stored XSS"]
    elif "dom" in lower_issue and "xss" in lower_issue:
        return REMEDIATION_MAPPING["DOM XSS"]
    elif "heartbleed" in lower_issue:
        return REMEDIATION_MAPPING["Heartbleed"]
    elif any(x in lower_issue for x in ["ssl", "tls"]) and "weak protocol" in lower_issue:
        return REMEDIATION_MAPPING["Weak Protocol"]
    elif any(x in lower_issue for x in ["weak cipher", "rc4", "des", "md5", "export"]):
        return REMEDIATION_MAPPING["Weak Cipher"]
    elif "forward secrecy" in lower_issue and "not supported" in lower_issue:
        return REMEDIATION_MAPPING["No PFS"]
    elif "cookie" in lower_issue:
        return REMEDIATION_MAPPING["Cookie"]
    elif any(x in lower_issue for x in ["header", "csp", "hsts", "x-frame", "content-type"]):
        return REMEDIATION_MAPPING["Missing Security Header"]
    elif any(x in lower_issue for x in ["server information", "information leakage", "version"]):
        return REMEDIATION_MAPPING["Server Information Leakage"]
    elif "directory traversal" in lower_issue:
        return REMEDIATION_MAPPING["Directory Traversal"]
    elif any(x in lower_issue for x in ["http method", "put", "delete", "trace"]):
        return REMEDIATION_MAPPING["Insecure HTTP Method"]
    elif "csrf" in lower_issue:
        return REMEDIATION_MAPPING["CSRF Vulnerability"]
    elif any(x in lower_issue for x in ["certificate", "cert"]):
        return REMEDIATION_MAPPING["SSL Certificate Issue"]
    
    # Default recommendation
    return {"severity": "Info", "recommendation": "Review this issue manually for specific remediation steps."}

def count_by_severity(results):
    """Counts vulnerabilities by severity level."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    for result in results:
        severity = result.get("severity", "Info")
        if severity in counts:
            counts[severity] += 1
        else:
            counts["Info"] += 1
            
    return counts

def clean_text_for_pdf(text):
    """
    Ensures text is ASCII-only to avoid encoding issues with FPDF.
    Replaces common Unicode characters with ASCII equivalents.
    """
    # Replace specific Unicode characters with ASCII equivalents
    replacements = {
        '\u2192': '->',  # Right arrow
        '\u2190': '<-',  # Left arrow
        '\u2018': "'",   # Left single quote
        '\u2019': "'",   # Right single quote
        '\u201c': '"',   # Left double quote
        '\u201d': '"',   # Right double quote
        '\u2013': '-',   # En dash
        '\u2014': '--',  # Em dash
        '\u2022': '*',   # Bullet
        '\u2026': '...', # Ellipsis
        '\u00a9': '(c)', # Copyright
        '\u00ae': '(R)', # Registered trademark
        '\u2122': '(TM)',# Trademark
        '\u00b0': ' degrees', # Degree sign
        '\u00b1': '+/-', # Plus-minus sign
        '\u2212': '-',   # Minus sign
        '\u00d7': 'x',   # Multiplication sign
        '\u00f7': '/',   # Division sign
        '\u20ac': 'EUR', # Euro sign
        '\u00a3': 'GBP', # Pound sign
        '\u00a5': 'JPY', # Yen sign
        '\u00a2': 'c',   # Cent sign
        '\u00a7': 'S',   # Section sign
        '\u00b6': 'P',   # Pilcrow sign
        '\u00a6': '|',   # Broken vertical bar
        '\u00a4': '$',   # Currency sign
        '\u03b1': 'alpha', # Alpha
        '\u03b2': 'beta', # Beta
        '\u03b3': 'gamma', # Gamma
        '\u03c0': 'pi',  # Pi
        '\u00ae': '(R)'  # Registered trademark
    }
    
    for unicode_char, ascii_char in replacements.items():
        text = text.replace(unicode_char, ascii_char)
    
    # Remove any remaining non-ASCII characters
    text = ''.join(c if ord(c) < 128 else ' ' for c in text)
    return text

def generate_pdf_report(url, scan_results, filename="scan_report.pdf", scan_time=None):
    """Generates an optimized PDF report with compact layout."""
    # Clean URL for PDF output
    url = clean_text_for_pdf(url)
    
    # Clean any Unicode characters in scan results
    for i in range(len(scan_results)):
        if "issue" in scan_results[i]:
            scan_results[i]["issue"] = clean_text_for_pdf(scan_results[i]["issue"])
    
    # Create PDF with compact layout
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    
    # Add report header and metadata with reduced spacing
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 8, f"Web Application Vulnerability Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 5, f"Target: {url}", ln=True, align="C")
    
    # Add scan metadata with compact spacing
    pdf.set_font("Arial", "", 8)
    pdf.cell(0, 4, f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    if scan_time:
        pdf.cell(0, 4, f"Scan Duration: {scan_time} seconds", ln=True)

    
    # Count vulnerabilities by severity
    severity_counts = count_by_severity(scan_results)
    
    # Add severity summary with compact layout
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, "Vulnerability Summary:", ln=True)
    pdf.set_font("Arial", "", 9)
    
    # Define colors for severity levels
    colors = {
        "Critical": (200, 0, 0),
        "High": (220, 50, 50),
        "Medium": (255, 140, 0),
        "Low": (0, 128, 0),
        "Info": (70, 130, 180)
    }
    
    # Add severity counts with color coding (compact format)
    for severity, count in severity_counts.items():
        if count > 0:
            pdf.set_text_color(*colors.get(severity, (0, 0, 0)))
            pdf.cell(0, 4, f"{severity}: {count}", ln=True)
    
    # Reset color
    pdf.set_text_color(0, 0, 0)
    
    # Group findings by category
    categories = {}
    for result in scan_results:
        issue = result.get("issue", "Unknown issue")
        category = "Other"
        
        # Determine category based on issue text
        if "sql" in issue.lower():
            category = "SQL Injection"
        elif "xss" in issue.lower():
            category = "Cross-Site Scripting (XSS)"
        elif any(x in issue.lower() for x in ["cookie", "csrf", "header"]):
            category = "Security Headers & Cookies"
        elif any(x in issue.lower() for x in ["ssl", "tls", "certificate", "cipher", "protocol"]):
            category = "SSL/TLS Configuration"
        elif any(x in issue.lower() for x in ["port", "method", "directory", "network"]):
            category = "Network Security"
            
        if category not in categories:
            categories[category] = []
        categories[category].append(result)
    
    # Add detailed findings by category (compact layout)
    pdf.set_font("Arial", "B", 10)
    pdf.ln(2)
    pdf.cell(0, 5, "Detailed Findings:", ln=True)
    
    # Process each category with minimal spacing
    for category, results in categories.items():
        pdf.set_font("Arial", "B", 9)
        pdf.ln(1)
        pdf.cell(0, 4, category, ln=True)
        
        # Sort findings by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "Info"), 999))
        
        # Process each finding with minimal spacing
        for result in results:
            issue = result.get("issue", "Unknown issue")
            severity = result.get("severity", "Info")
            
            # Map to remediation
            remediation_info = map_vulnerability(issue)
            recommendation = remediation_info.get("recommendation", "Review manually.")
            
            # Clean recommendation text
            recommendation = clean_text_for_pdf(recommendation)
            
            # Set color based on severity
            pdf.set_text_color(*colors.get(severity, (0, 0, 0)))
            
            # Add finding with minimal spacing
            pdf.set_font("Arial", "B", 8)
            pdf.cell(0, 4, f"{severity}: {issue}", ln=True)
            
            # Add recommendation with minimal spacing
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 7)
            pdf.multi_cell(0, 3, f"Recommendation: {recommendation}")
    
    # Add remediation guidance section with minimal spacing
    pdf.ln(2)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 5, "General Remediation Guidance", ln=True)
    
    # Create compact two-column layout for general recommendations using compatible approach
    general_recommendations = [
        ("Input Validation", "Implement strict input validation for all user-supplied data using whitelisting approach."),
        ("Output Encoding", "Apply context-specific output encoding for all data displayed to users."),
        ("Authentication", "Use multi-factor authentication and implement proper session management."),
        ("Authorization", "Apply principle of least privilege and role-based access control."),
        ("Secure Configuration", "Harden web servers, frameworks, and database systems."),
        ("Error Handling", "Implement custom error pages that don't reveal sensitive information."),
        ("Logging & Monitoring", "Establish comprehensive logging and monitoring for security events."),
        ("Data Protection", "Encrypt sensitive data both in transit and at rest."),
        ("Security Headers", "Implement all recommended security headers including CSP."),
        ("Security Testing", "Conduct regular security assessments and penetration testing.")
    ]
    
    pdf.set_font("Arial", "", 7)
    col_width = 95
    
    # Split recommendations into two columns
    for i in range(0, len(general_recommendations), 2):
        topic1, details1 = general_recommendations[i]
        
        # First column header
        pdf.set_font("Arial", "B", 7)
        pdf.cell(col_width, 3, topic1)
        
        # If we have a second column
        if i + 1 < len(general_recommendations):
            topic2, details2 = general_recommendations[i + 1]
            # Second column header
            pdf.cell(col_width, 3, topic2, ln=True)
            
            # First column details
            current_x = pdf.get_x()
            current_y = pdf.get_y()
            pdf.set_font("Arial", "", 6)
            pdf.multi_cell(col_width, 3, clean_text_for_pdf(details1))
            
            # Second column details (using absolute positioning)
            pdf.set_xy(current_x + col_width, current_y)
            pdf.multi_cell(col_width, 3, clean_text_for_pdf(details2))
        else:
            # Only one column for the last row
            pdf.ln(1)
            pdf.set_font("Arial", "", 6)
            pdf.multi_cell(col_width, 3, clean_text_for_pdf(details1))
    
    # Add footer with timestamp
    pdf.set_y(-10)
    pdf.set_font('Arial', 'I', 7)
    pdf.cell(0, 5, f'Scan generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, 'C')
    
    # Ensure the reports directory exists
    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/{filename}"
    pdf.output(report_path)
    
    return report_path