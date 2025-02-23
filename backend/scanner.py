import yara
import pefile
import hashlib
import math
import re
from docx import Document
from PyPDF2 import PdfReader

# Load YARA rules
try:
    RULES = yara.compile(filepath="backend/yara_rules.yar")
except Exception as e:
    print(f"⚠️ Error loading YARA rules: {e}")
    RULES = None

def get_file_hash(file_path):
    """Compute SHA-256 hash of a file."""
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def scan_with_yara(file_path):
    """Scan a file with YARA rules."""
    if RULES:
        matches = RULES.match(file_path)
        return [match.rule for match in matches]
    return []

def analyze_pe_file(file_path):
    """Analyze a PE file for suspicious characteristics."""
    try:
        pe = pefile.PE(file_path)
        sections = []
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            sections.append({
                "name": section.Name.decode().strip(),
                "entropy": entropy,
                "suspicious": entropy > 7.0
            })
        return {"sections": sections, "suspicious": any(s["suspicious"] for s in sections)}
    except Exception as e:
        return {"error": f"PE analysis failed: {str(e)}"}

def check_for_macros(file_path):
    """Check for macros in a .docx file."""
    try:
        doc = Document(file_path)
        if doc.core_properties.keywords == "Macros":
            return True
        return False
    except Exception as e:
        return {"error": f"Macro detection failed: {str(e)}"}

def analyze_pdf(file_path):
    """Analyze a PDF file for suspicious objects."""
    try:
        reader = PdfReader(file_path)
        return {"suspicious": any("/JavaScript" in page.get_object() for page in reader.pages)}
    except Exception as e:
        return {"error": f"PDF analysis failed: {str(e)}"}

