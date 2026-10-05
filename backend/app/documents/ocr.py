import os
import shutil
import logging
import numpy as np
import cv2
import pytesseract
import pymupdf
from PIL import Image

from backend.app.common.errors import AppError

logger = logging.getLogger("intel_protect.ocr")


class OCRError(AppError):
    def __init__(self, message="OCR processing failed.", code="OCR_PROCESSING_FAILED"):
        super().__init__(message=message, code=code, status_code=422)


def get_tesseract_cmd() -> str:
    """
    Locates the Tesseract executable path across environment variables,
    standard Windows install locations, and system PATH.
    """
    env_path = os.getenv("TESSERACT_CMD")
    if env_path and os.path.exists(env_path):
        return env_path

    # Standard Windows install locations
    common_windows_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for path in common_windows_paths:
        if os.path.exists(path):
            return path

    # System PATH lookup
    system_path = shutil.which("tesseract")
    if system_path:
        return system_path

    return "tesseract"


# Initialize pytesseract command
pytesseract.pytesseract.tesseract_cmd = get_tesseract_cmd()


def preprocess_image_for_ocr(img_bgr: np.ndarray) -> np.ndarray:
    """
    Comprehensive OpenCV image preprocessing pipeline for OCR:
    1. Grayscale conversion
    2. Dynamic resizing for low-resolution inputs
    3. Noise reduction via Gaussian blur
    4. Otsu's automatic thresholding (binarization)
    5. Deskewing to normalize rotated text
    """
    if img_bgr is None or img_bgr.size == 0:
        raise OCRError("Empty or corrupted image provided for preprocessing.", code="INVALID_IMAGE")

    # 1. Grayscale
    if len(img_bgr.shape) == 3:
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    else:
        gray = img_bgr.copy()

    # 2. Resizing: If width is small, upscale with bicubic interpolation
    h, w = gray.shape
    if w < 1200:
        scale_factor = 1200.0 / w
        gray = cv2.resize(gray, (int(w * scale_factor), int(h * scale_factor)), interpolation=cv2.INTER_CUBIC)

    # 3. Noise reduction
    denoised = cv2.GaussianBlur(gray, (3, 3), 0)

    # 4. Otsu's Binarization
    _, binary = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # 5. Deskewing
    try:
        # Invert binary image to find text pixels
        inv_binary = cv2.bitwise_not(binary)
        coords = np.column_stack(np.where(inv_binary > 0))
        if len(coords) > 50:
            angle = cv2.minAreaRect(coords)[-1]
            if angle < -45:
                angle = -(90 + angle)
            elif angle > 45:
                angle = 90 - angle

            # Only rotate if tilt is noticeable (> 0.5 degrees and < 45 degrees)
            if 0.5 < abs(angle) < 45:
                (h_bin, w_bin) = binary.shape
                center = (w_bin // 2, h_bin // 2)
                m = cv2.getRotationMatrix2D(center, angle, 1.0)
                binary = cv2.warpAffine(
                    binary, m, (w_bin, h_bin),
                    flags=cv2.INTER_CUBIC,
                    borderMode=cv2.BORDER_REPLICATE
                )
    except Exception as e:
        logger.debug(f"Deskew skipped: {e}")

    return binary


def extract_text_from_image(file_path: str) -> str:
    """
    Extracts text from a PNG or JPG/JPEG image file using OpenCV + Tesseract OCR.
    """
    try:
        with open(file_path, "rb") as f:
            img_bytes = f.read()
        nparr = np.frombuffer(img_bytes, np.uint8)
        img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img_bgr is None:
            raise OCRError("Unable to decode image file.", code="IMAGE_DECODE_FAILED")

        processed = preprocess_image_for_ocr(img_bgr)

        # Run Tesseract OCR (LSTM engine, automatic page segmentation)
        config = "--oem 3 --psm 3"
        text = pytesseract.image_to_string(processed, config=config, lang="eng")
        return text.strip()
    except OCRError:
        raise
    except pytesseract.TesseractNotFoundError:
        logger.error("Tesseract OCR binary not found on system PATH.")
        raise OCRError(
            "Tesseract OCR is not installed or configured on the server. Please verify system dependencies.",
            code="TESSERACT_NOT_INSTALLED"
        )
    except Exception as e:
        logger.error(f"Image OCR failed: {e}")
        raise OCRError(f"OCR execution failed: {str(e)}")


def extract_text_from_scanned_pdf(file_path: str) -> tuple[str, int]:
    """
    Fallback OCR for scanned or image-only PDFs.
    Renders pages at 200 DPI, preprocesses with OpenCV, and executes Tesseract OCR.
    """
    try:
        with open(file_path, "rb") as f:
            pdf_bytes = f.read()
    except Exception as e:
        raise OCRError(f"Unable to read PDF for OCR: {str(e)}", code="CANNOT_READ_FILE")

    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        raise OCRError(f"Unable to open PDF for OCR: {str(e)}", code="CORRUPTED_PDF")

    try:
        total_pages = len(doc)
        ocr_pages_text = []

        for page_num in range(total_pages):
            page = doc.load_page(page_num)
            # Render page at 200 DPI for reliable OCR
            pix = page.get_pixmap(dpi=200)

            # Convert pixmap bytes to numpy array
            img_bytes = pix.tobytes("png")
            nparr = np.frombuffer(img_bytes, np.uint8)
            img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img_bgr is not None:
                processed = preprocess_image_for_ocr(img_bgr)
                text = pytesseract.image_to_string(processed, lang="eng", config="--oem 3 --psm 3")
                if text.strip():
                    ocr_pages_text.append(text.strip())

            del pix
            del page

        full_text = "\n\n".join(ocr_pages_text)
        return full_text, total_pages
    except pytesseract.TesseractNotFoundError:
        raise OCRError("Tesseract OCR is not installed or configured on the server.", code="TESSERACT_NOT_INSTALLED")
    except Exception as e:
        logger.error(f"Scanned PDF OCR failed: {e}")
        raise OCRError(f"Scanned PDF OCR failed: {str(e)}")
    finally:
        doc.close()
        del doc
