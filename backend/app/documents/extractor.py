import pymupdf
from backend.app.common.errors import AppError


class ExtractionError(AppError):
    def __init__(self, message="Document extraction failed.", code="EXTRACTION_FAILED"):
        super().__init__(message=message, code=code, status_code=422)


def extract_text_from_pdf(file_path: str) -> tuple[str, int]:
    """
    Extracts text from a PDF file using PyMuPDF.
    Returns (extracted_text, page_count).
    """
    try:
        with open(file_path, "rb") as f:
            pdf_bytes = f.read()
    except Exception as e:
        raise ExtractionError(f"Unable to read PDF file: {str(e)}", code="CANNOT_READ_FILE")

    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        raise ExtractionError(f"Unable to read or parse PDF file: {str(e)}", code="CORRUPTED_PDF")

    try:
        pages_text = []
        total_pages = len(doc)
        if total_pages == 0:
            raise ExtractionError("PDF document has 0 pages.", code="EMPTY_PDF")

        for page_num in range(total_pages):
            page = doc.load_page(page_num)
            text = page.get_text("text") or ""
            pages_text.append(text.strip())
            del page

        full_text = "\n\n".join(filter(None, pages_text))
        return full_text, total_pages
    except ExtractionError:
        raise
    except Exception as e:
        raise ExtractionError(f"Error extracting text from PDF: {str(e)}")
    finally:
        doc.close()
        del doc


def extract_text_from_txt(file_path: str) -> str:
    """
    Extracts plain text from a TXT file with UTF-8 / fallback decoding.
    """
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return raw_bytes.decode("latin-1", errors="replace")
    except Exception as e:
        raise ExtractionError(f"Error reading text document: {str(e)}")
