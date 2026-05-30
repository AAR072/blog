#!/usr/bin/env python3
"""Convert the first page of static/Ali_Raza_resume.pdf to static/resume.png."""

import subprocess
import sys
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pymupdf"])
    import fitz

pdf_path = Path(__file__).parent / "static" / "Ali_Raza_resume.pdf"
png_path = Path(__file__).parent / "static" / "resume.png"

if not pdf_path.exists():
    print(f"Error: {pdf_path} not found. Drop your resume PDF there first.")
    sys.exit(1)

doc = fitz.open(pdf_path)
page = doc[0]
# 2x scale → ~150 dpi, crisp on retina without being huge
mat = fitz.Matrix(2, 2)
pix = page.get_pixmap(matrix=mat)
pix.save(png_path)
doc.close()

print(f"Saved {png_path} ({pix.width}x{pix.height}px)")
