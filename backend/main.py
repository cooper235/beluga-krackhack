from fastapi import FastAPI, File, UploadFile, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
import os
import yara
import pefile
import hashlib
import math
import sqlite3
from docx import Document
from PyPDF2 import PdfReader
import re

# Initialize FastAPI app
app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Constants
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Load YARA rules
try:
    RULES = yara.compile(filepath="backend/yara_rules.yar")
except Exception as e:
    print(f"⚠️ Error loading YARA rules: {e}")
    RULES = None

# Initialize SQLite database
conn = sqlite3.connect("scans.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        verdict TEXT,
        yara_matches TEXT,
        pe_info TEXT,
        file_hash TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.commit()

# Helper Functions
def sanitize_filename(filename):
    """Sanitize file names to prevent path traversal."""
    return re.sub(r"[^\w\.-]", "_", filename)

def is_allowed_file(filename):
    """Check if the file extension is allowed."""
    return any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS)

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
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            sections.append({
                "name": section.Name.decode().strip(),
                "entropy": entropy,
                "suspicious": entropy > 7.0  # High entropy threshold
            })
        return {"sections": sections, "suspicious": any(s["suspicious"] for s in sections)}
    except Exception as e:
        return {"error": f"PE analysis failed: {str(e)}"}

def check_for_macros(file_path):
    """Check for macros in a .docx file."""
    try:
        doc = Document(file_path)
        # Check for macros (simplified example)
        if doc.core_properties.keywords == "Macros":
            return True
        return False
    except Exception as e:
        return {"error": f"Macro detection failed: {str(e)}"}

def analyze_pdf(file_path):
    """Analyze a PDF file for suspicious objects."""
    try:
        reader = PdfReader(file_path)
        suspicious = False
        for page in reader.pages:
            if "/JavaScript" in page.get_object():
                suspicious = True
        return {"suspicious": suspicious}
    except Exception as e:
        return {"error": f"PDF analysis failed: {str(e)}"}

def save_scan_result(filename, verdict, yara_matches, pe_info, file_hash):
    """Save scan results to the database."""
    cursor.execute("""
        INSERT INTO scans (filename, verdict, yara_matches, pe_info, file_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (filename, verdict, str(yara_matches), str(pe_info), file_hash))
    conn.commit()

# API Endpoints
@app.get("/")
def read_root():
    return {"message": "Welcome to the Malware Analysis API!"}

@app.post("/scan/")
@limiter.limit("5/minute")
async def scan_file(file: UploadFile = File(...)):
    """Handle file uploads and scan for malware indicators."""
    # Validate file type
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Allowed: .exe, .pdf, .docx")

    # Read file contents and validate size
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (Max: 5MB).")

    # Save file temporarily
    sanitized_filename = sanitize_filename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, sanitized_filename)
    with open(file_path, "wb") as f:
        f.write(contents)

    # Perform malware analysis
    yara_matches = scan_with_yara(file_path)
    file_hash = get_file_hash(file_path)
    pe_info = analyze_pe_file(file_path) if file.filename.endswith(".exe") else None
    macros_detected = check_for_macros(file_path) if file.filename.endswith(".docx") else None
    pdf_analysis = analyze_pdf(file_path) if file.filename.endswith(".pdf") else None

    # Determine verdict
    verdict = "Clean"
    risk_factors = []
    if yara_matches:
        verdict = "Malicious"
        risk_factors.append(f"YARA matches: {yara_matches}")
    if pe_info and pe_info.get("suspicious"):
        verdict = "Malicious"
        risk_factors.append("Suspicious PE sections detected.")
    if macros_detected:
        verdict = "Malicious"
        risk_factors.append("Macros detected in .docx file.")
    if pdf_analysis and pdf_analysis.get("suspicious"):
        verdict = "Malicious"
        risk_factors.append("Suspicious PDF objects detected.")

    # Save scan results to database
    save_scan_result(file.filename, verdict, yara_matches, pe_info, file_hash)

    # Clean up temporary file
    os.remove(file_path)

    # Return results
    return {
        "filename": file.filename,
        "verdict": verdict,
        "risk_factors": risk_factors,
        "yara_matches": yara_matches,
        "pe_info": pe_info,
        "file_hash": file_hash
    }
