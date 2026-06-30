"""
Text extractor for uploaded documents.

Supports PDF (via pdfplumber) and .docx (via python-docx).
All failures are surfaced as ExtractionError — callers never see raw exceptions.

Design notes:
- pdfplumber handles text-layer PDFs; image-only PDFs will yield empty text.
- We detect empty/image-only PDFs explicitly and raise a clear error message,
  rather than silently inserting a document with no content.
- python-docx raises PackageNotFoundError for corrupt/non-docx files;
  we catch all exceptions and re-raise as ExtractionError.
"""

import io
from typing import Tuple


class ExtractionError(Exception):
    """Raised for any extraction failure — corrupt file, wrong type, no text layer, etc."""
    pass


def extract_text(filename: str, content: bytes) -> Tuple[str, str]:
    """
    Extract plain text from PDF or .docx bytes.

    Args:
        filename: Original filename (used to determine type by extension)
        content:  Raw file bytes

    Returns:
        (text, detected_type) where detected_type is 'pdf' or 'docx'

    Raises:
        ExtractionError: With a human-readable message for the frontend
    """
    lower = filename.lower()

    if lower.endswith('.pdf'):
        return _extract_pdf(content), 'pdf'
    elif lower.endswith('.docx'):
        return _extract_docx(content), 'docx'
    else:
        raise ExtractionError(
            f"Unsupported file type '{filename}'. Please upload a PDF (.pdf) or Word document (.docx)."
        )


def _extract_pdf(content: bytes) -> str:
    try:
        import pdfplumber
    except ImportError:
        raise ExtractionError("PDF support is not installed. Contact the administrator.")

    try:
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            if len(pdf.pages) == 0:
                raise ExtractionError("The PDF has no pages.")

            pages_text = []
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    pages_text.append(page_text.strip())

            text = "\n\n".join(pages_text).strip()

    except ExtractionError:
        raise
    except Exception as e:
        raise ExtractionError(
            f"Could not read the PDF. The file may be corrupted or password-protected. ({type(e).__name__})"
        )

    if not text:
        raise ExtractionError(
            "No text could be extracted from this PDF. It appears to be a scanned "
            "image-only PDF with no text layer. Please use a PDF with selectable text, "
            "or convert it with OCR first."
        )

    return text


def _extract_docx(content: bytes) -> str:
    try:
        from docx import Document as DocxDocument
    except ImportError:
        raise ExtractionError("Word document support is not installed. Contact the administrator.")

    try:
        doc = DocxDocument(io.BytesIO(content))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        text = "\n\n".join(paragraphs).strip()
    except Exception as e:
        raise ExtractionError(
            f"Could not read the Word document. The file may be corrupted or not a valid .docx file. ({type(e).__name__})"
        )

    if not text:
        raise ExtractionError(
            "No text could be extracted from this Word document. The document appears to be empty."
        )

    return text
