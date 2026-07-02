import io
import pandas as pd
import pdfplumber
import fitz  # PyMuPDF
import pytesseract
from PIL import Image

def parse_txt(file_bytes: bytes) -> str:
    """Decodes plain text with fallback encoding detection."""
    try:
        return file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return file_bytes.decode("latin-1")

def parse_csv(file_bytes: bytes) -> str:
    """Parses CSV content and converts it to a readable string representation."""
    df = pd.read_csv(io.BytesIO(file_bytes))
    return df.to_string(index=False)

def parse_pdf(file_bytes: bytes) -> tuple[str, list[dict]]:
    """
    Parses PDF using pdfplumber to extract text and page metadata.
    If the document yields negligible text, falls back to pytesseract OCR.
    Returns:
        tuple: (full_extracted_text, list of page dicts)
    """
    text = ""
    pages_data = []
    
    # Try pdfplumber text extraction
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for idx, page in enumerate(pdf.pages):
                page_text = page.extract_text() or ""
                text += page_text + "\n"
                pages_data.append({
                    "page_num": idx + 1,
                    "text": page_text,
                    "width": float(page.width),
                    "height": float(page.height)
                })
    except Exception as e:
        # If pdfplumber fails, log/propagate or prepare for OCR fallback
        text = ""
        pages_data = []

    # Clean and check if we extracted sufficient text characters
    cleaned_text = text.strip()
    if len(cleaned_text) < 15:
        # Attempt OCR
        text, pages_data = parse_pdf_ocr(file_bytes)
        
    return text, pages_data

def parse_pdf_ocr(file_bytes: bytes) -> tuple[str, list[dict]]:
    """
    Performs OCR scanning on PDF pages using PyMuPDF to render pages
    to PNG pixmaps and Tesseract OCR to perform text recognition.
    """
    text = ""
    pages_data = []
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception as e:
        raise ValueError(f"Failed to open PDF binary file: {str(e)}")
        
    for idx, page in enumerate(doc):
        # Render page to high-quality image (150 DPI is a good balance of speed and OCR quality)
        pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))
        img_data = pix.tobytes("png")
        img = Image.open(io.BytesIO(img_data))
        
        try:
            page_text = pytesseract.image_to_string(img)
        except pytesseract.TesseractNotFoundError:
            raise RuntimeError(
                "Tesseract OCR binary not found. Scanned PDF processing is disabled. "
                "Please install Tesseract OCR on your system and add it to your system PATH."
            )
        except Exception as e:
            raise RuntimeError(f"Tesseract OCR extraction failed: {str(e)}")
            
        text += page_text + "\n"
        pages_data.append({
            "page_num": idx + 1,
            "text": page_text,
            "width": float(page.rect.width),
            "height": float(page.rect.height)
        })
        
    return text, pages_data
