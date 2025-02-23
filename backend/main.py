from fastapi import FastAPI, File, UploadFile, HTTPException
import os
import yara
import pefile
import hashlib

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Define Allowed File Extensions & Size Limit
ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Load YARA Rules from File (Ensure 'rules.yar' Exists in Project Folder)
try:
    RULES = yara.compile(filepath="backend/yara_rules.yar")

except Exception as e:
    print(f"⚠️ Error loading YARA rules: {e}")
    RULES = None
@app.get("/")
def read_root():
    return {"message": "Welcome to the Malware Analysis API!"}
# Function to Validate Allowed File Types
def is_allowed_file(filename):
    return any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS)

# Function to Compute SHA-256 Hash of a File
def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# Function to Scan File with YARA
def scan_with_yara(file_path):
    if RULES:
        matches = RULES.match(file_path)
        return [match.rule for match in matches]
    return []

# Function to Analyze PE Files (Only for `.exe` Files)
def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        sections = [section.Name.decode().strip() for section in pe.sections]
        return {"sections": sections, "suspicious": ".text" not in sections}
    except Exception as e:
        return {"error": f"PE analysis failed: {str(e)}"}

@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    """Handle File Uploads & Scan for Malware Indicators"""

    # Validate File Type
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Allowed: .exe, .pdf, .docx")

    # Read File Contents & Validate Size
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (Max: 5MB).")

    # Save File Temporarily
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(contents)

    # Perform Malware Analysis
    yara_matches = scan_with_yara(file_path)
    file_hash = get_file_hash(file_path)
    pe_info = analyze_pe_file(file_path) if file.filename.endswith(".exe") else None

    # Clean Up Temporary File
    os.remove(file_path)

    # Determine Verdict
    verdict = "Malicious" if yara_matches or (pe_info and pe_info.get("suspicious")) else "Clean"

    return {
        "filename": file.filename,
        "verdict": verdict,
        "yara_matches": yara_matches,
        "pe_info": pe_info,
        "file_hash": file_hash
    }
