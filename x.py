from fpdf import FPDF

def create_basic_pdf_fpdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Hello, this is a test PDF!", ln=True, align='C')
    pdf.output("test_output_fpdf.pdf")

    print("PDF Created successfully with fpdf!")

create_basic_pdf_fpdf()
