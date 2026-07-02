import os
import csv
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Create test_files directory if not exists
os.makedirs("test_files", exist_ok=True)

# 1. Create PII TXT file
pii_txt_content = """Subject: Internal Security Audit and Developer Configurations

Hi Team,
Here are the credential configs and contact updates from yesterday's migration.

1. General Support Contact:
- Coordinator Name: Rajeev Sharma
- Email: rajeev.sharma@example.co.in
- Direct Mobile: +91 98765 43210 (Alternate: 08765432109)

2. Critical System Credentials (TO BE MOVED TO SECRET MANAGER IMMEDIATELY):
- Production OpenAI Key: sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3
- Backup Dev API Token: gsk_dev_secret_token_90210_xyz_alpha_omega_entropy_12345
- Encryption password seed: hash_salt_value_entropy_998877

3. User Compliance Records for Verification:
- User Profile 1: Sunita Patel
- Aadhaar Number: 5432 9012 3456
- PAN Card: ABCDE1234F

Please verify the above data feeds and purge this email log when complete.

Best Regards,
SecOps Team
"""

with open(os.path.join("test_files", "test_pii.txt"), "w", encoding="utf-8") as f:
    f.write(pii_txt_content)


# 2. Create Employee Compliance CSV file
csv_headers = ["Employee_Name", "Employee_ID", "PAN_Number", "Contact_Email", "IFSC_Code", "Bank_Account"]
csv_rows = [
    ["Amit Verma", "EMP-2091", "PQRTS5678A", "amit.verma@company.com", "SBIN0001234", "123456789012"],
    ["Priya Nair", "EMP-3102", "JKLMN4321Z", "priya.nair@company.com", "HDFC0000080", "98765432109876"],
    ["Rohan Das", "EMP-9021", "VWXYZ9876B", "rohan.das@company.com", "ICIC0000102", "456789012345"]
]

with open(os.path.join("test_files", "test_compliance.csv"), "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)
    writer.writerows(csv_rows)


# 3. Create Corporate PDF using ReportLab
pdf_path = os.path.join("test_files", "test_corporate.pdf")
doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    'DocTitle',
    parent=styles['Title'],
    fontName='Helvetica-Bold',
    fontSize=22,
    textColor=colors.HexColor("#1e3a8a"),
    spaceAfter=15
)
body_style = ParagraphStyle(
    'ReportBody',
    parent=styles['BodyText'],
    fontSize=10,
    leading=14
)

story = []
story.append(Paragraph("PROJECT QUANTUM SECRET STRATEGY DOCUMENT", title_style))
story.append(Spacer(1, 10))

story.append(Paragraph(
    "<b>Classification: CONFIDENTIAL BUSINESS INFORMATION (INTERNAL ONLY)</b>", body_style
))
story.append(Spacer(1, 10))

story.append(Paragraph(
    "Project Quantum aims to expand our financial services market share in Q3 2026. "
    "We are planning a secret acquisition of FinTech partners to build next-generation credit score systems. "
    "To support initial integrations, we have set up sandboxed billing credentials in our staging server. "
    "These credentials will link directly to a corporate test visa card.",
    body_style
))
story.append(Spacer(1, 15))

story.append(Paragraph(
    "<b>Staging Billing Coordinates (To be removed before launch):</b><br/>"
    "- Billing Coordinator: Anita Sen<br/>"
    "- Contact Email: anita.sen@quantumproject.internal<br/>"
    "- Primary Testing Visa Card: 4111 1111 1111 1111 (Expiry 12/28, CVV 901)<br/>"
    "- Alternate Testing Master Card: 5105 1051 0510 5105<br/>"
    "- Vault API Key: AIzaSyD4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9",
    body_style
))
story.append(Spacer(1, 15))

story.append(Paragraph(
    "If any leaks are suspected, contact security compliance immediately. All actions must be compliant "
    "with ISO 27001 policies and GDPR data retention schedules.",
    body_style
))

doc.build(story)

print("Test files generated successfully inside 'test_files' folder!")
