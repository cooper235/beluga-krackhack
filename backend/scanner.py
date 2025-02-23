import yara
import pefile
import hashlib
import olefile
import math
import re
import json
from collections import Counter
from io import BytesIO
from PyPDF2 import PdfReader

# Load YARA Rules
try:
    RULES = yara.compile(filepath="backend/yara_rules.yar")
except Exception as e:
    print(f"⚠️ Error loading YARA rules: {e}")
    RULES = None

def get_file_hash(contents: bytes):
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(contents).hexdigest()

def calculate_entropy(data: bytes):
    """Calculate Shannon entropy for detecting packed/encrypted content."""
    if not data:
        return 0
    count = Counter(data)
    length = len(data)
    return -sum((freq / length) * math.log2(freq / length) for freq in count.values())

def scan_with_yara(contents: bytes):
    """Scan file contents using YARA rules (in-memory scanning)."""
    try:
        if RULES:
            matches = RULES.match(data=contents)
            return [match.rule for match in matches]
    except yara.Error as e:
        return {"error": f"YARA scan failed: {str(e)}"}
    return []

def analyze_pe_file(contents: bytes):
    """Analyze PE files for suspicious characteristics (in-memory parsing)."""
    try:
        pe = pefile.PE(data=contents)
        sections = []
        suspicious_imports = []

        # Analyze PE Sections
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            sections.append({
                "name": section.Name.decode(errors="ignore").strip(),
                "entropy": entropy,
                "suspicious": entropy > 7.0
            })

        # Check for Suspicious Imports (e.g., functions often used in malware)
        SUSPICIOUS_IMPORTS = {
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread"
        }
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode(errors="ignore") in SUSPICIOUS_IMPORTS:
                        suspicious_imports.append(imp.name.decode(errors="ignore"))

        return {
            "sections": sections,
            "suspicious": any(s["suspicious"] for s in sections) or bool(suspicious_imports),
            "suspicious_imports": suspicious_imports
        }
    except Exception as e:
        return {"error": f"PE analysis failed: {str(e)}"}

def check_for_macros(contents: bytes):
    """Detect presence of VBA macros in .doc or .docx files."""
    try:
        with BytesIO(contents) as file_stream:
            if olefile.isOleFile(file_stream):
                ole = olefile.OleFileIO(file_stream)
                return any(["VBA" in entry for entry in ole.listdir()])
    except Exception as e:
        return {"error": f"Macro detection failed: {str(e)}"}
    return False

def analyze_pdf(contents: bytes):
    """Analyze PDF for JavaScript and suspicious objects."""
    try:
        reader = PdfReader(BytesIO(contents))
        suspicious = False
        for page in reader.pages:
            text = json.dumps(page.get_object(), default=str)  # Convert PDF objects to JSON string
            if "/JavaScript" in text or "/JS" in text or "/Launch" in text:
                suspicious = True
                break
        return {"suspicious": suspicious} if suspicious else None
    except Exception as e:
        return {"error": f"PDF analysis failed: {str(e)}"}

def scan_file_content(contents: bytes, filename: str):
    """Perform all static analysis checks on the uploaded file."""

    # Compute File Hash
    file_hash = get_file_hash(contents)

    # YARA Scanning
    yara_matches = scan_with_yara(contents)

    # Format-specific Analysis
    pe_info = analyze_pe_file(contents) if filename.endswith(".exe") else None
    macros_detected = check_for_macros(contents) if filename.endswith((".doc", ".docx")) else None
    pdf_analysis = analyze_pdf(contents) if filename.endswith(".pdf") else None

    # Determine Verdict
    verdict = "Clean"
    risk_factors = []
    if yara_matches:
        verdict = "Malicious"
        risk_factors.append(f"YARA matches: {yara_matches}")
    if pe_info and pe_info.get("suspicious"):
        verdict = "Malicious"
        risk_factors.append("Suspicious PE sections or imports detected.")
    if macros_detected:
        verdict = "Malicious"
        risk_factors.append("Macros detected in document.")
    if pdf_analysis:
        verdict = "Malicious"
        risk_factors.append("Suspicious PDF objects detected.")

    return {
        "filename": filename,
        "verdict": verdict,
        "risk_factors": risk_factors,
        "yara_matches": yara_matches,
        "pe_info": pe_info,
        "file_hash": file_hash
    }
