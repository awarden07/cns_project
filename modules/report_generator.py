from fpdf import FPDF

def generate_pdf_report(scan_results, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, "Web Application Vulnerability Scan Report", ln=True, align="C")
    pdf.ln(10)

    for result in scan_results:
        pdf.multi_cell(0, 10, result)

    pdf.output(filename)
    return filename
