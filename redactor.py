import fitz
import io

SEVERITY_COLORS = {
    "Critical": "#ff6b6b",  # Coral Red
    "High": "#ff9f43",      # Orange
    "Medium": "#feca57",    # Yellow
    "Low": "#54a0ff"        # Light Blue
}

def generate_html_highlighted_text(text: str, findings: list[dict]) -> str:
    """
    Inserts HTML styling spans into raw text to highlight sensitive discoveries
    in a color-coded format based on severity level.
    Modifies strings from end to start to preserve index offsets.
    """
    # Sort findings by start index in descending order
    sorted_findings = sorted(
        [f for f in findings if f.get("start", 0) != f.get("end", 0)],
        key=lambda x: x["start"],
        reverse=True
    )
    
    html_text = text
    
    for f in sorted_findings:
        start = f["start"]
        end = f["end"]
        val = html_text[start:end]
        
        # Double check that characters match roughly (to avoid alignment shifts)
        if val.strip() == "":
            continue
            
        color = SEVERITY_COLORS.get(f.get("severity", "Low"), "#eeeeee")
        conf_pct = int(f["confidence"] * 100) if f["confidence"] <= 1.0 else int(f["confidence"])
        
        span = (
            f'<span style="background-color: {color}; color: #000000; padding: 1px 4px; '
            f'border-radius: 3px; font-weight: 500; border-bottom: 1px solid rgba(0,0,0,0.2);" '
            f'title="{f["type"]} ({f["method"]}) - Confidence: {conf_pct}%">'
            f'{val}'
            f'</span>'
        )
        html_text = html_text[:start] + span + html_text[end:]
        
    # Convert newlines to HTML breaks for Streamlit rendering
    return html_text.replace("\n", "<br>")

def mask_text_content(text: str, findings: list[dict]) -> str:
    """
    Replaces sensitive terms in plaintext with a redacted token label.
    Modifies strings from end to start to preserve index offsets.
    """
    sorted_findings = sorted(
        [f for f in findings if f.get("start", 0) != f.get("end", 0)],
        key=lambda x: x["start"],
        reverse=True
    )
    
    masked_text = text
    for f in sorted_findings:
        start = f["start"]
        end = f["end"]
        label = f"[{f['type'].upper()}_REDACTED]"
        masked_text = masked_text[:start] + label + masked_text[end:]
        
    return masked_text

def highlight_binary_pdf(pdf_bytes: bytes, findings: list[dict]) -> bytes:
    """
    Draws highlighted rectangle annotations on PDF coordinates for sensitive findings
    using PyMuPDF (fitz) text search capabilities.
    """
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        # Fallback if bytes are invalid
        return pdf_bytes
        
    # Extract unique values to search for, avoiding duplicate drawing
    target_values = set(f["value"] for f in findings if f.get("value"))
    
    for page in doc:
        for val in target_values:
            # Search for instances of the text on this page
            rects = page.search_for(val)
            for rect in rects:
                annot = page.add_highlight_annot(rect)
                # Soft yellow highlight color: (1, 0.9, 0.4)
                annot.set_colors(stroke=(1, 0.9, 0.4))
                annot.update()
                
    output = io.BytesIO()
    doc.save(output)
    doc.close()
    return output.getvalue()

def redact_binary_pdf(pdf_bytes: bytes, findings: list[dict]) -> bytes:
    """
    Draws black redaction blocks on PDF coordinates and executes PyMuPDF's
    apply_redactions to completely purge the sensitive characters from the PDF document structure.
    """
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        return pdf_bytes
        
    target_values = set(f["value"] for f in findings if f.get("value"))
    
    for page in doc:
        for val in target_values:
            rects = page.search_for(val)
            for rect in rects:
                # Add a redaction annotation with black fill (0, 0, 0)
                page.add_redact_annot(rect, fill=(0, 0, 0))
        # Execute the redaction to burn in black blocks and erase the underlying text characters
        page.apply_redactions()
        
    output = io.BytesIO()
    doc.save(output)
    doc.close()
    return output.getvalue()
