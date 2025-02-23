from fastapi import FastAPI, File, UploadFile, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
import os
from models import save_scan_result
from scanner import scan_with_yara, analyze_pe_file, check_for_macros, analyze_pdf, get_file_hash

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.get("/")
def read_root():
    return {"message": "Welcome to the Malware Analysis API!"}

@app.post("/scan/")
@limiter.limit("5/minute")
async def scan_file(file: UploadFile = File(...)):
    """Handle file uploads and scan for malware indicators."""
    if not any(file.filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Invalid file type.")

    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (Max: 5MB).")

    sanitized_filename = re.sub(r"[^\w\.-]", "_", file.filename)
    file_path = os.path.join(UPLOAD_DIR, sanitized_filename)
    with open(file_path, "wb") as f:
        f.write(contents)

    yara_matches = scan_with_yara(file_path)
    file_hash = get_file_hash(file_path)
    pe_info = analyze_pe_file(file_path) if file.filename.endswith(".exe") else None
    macros_detected = check_for_macros(file_path) if file.filename.endswith(".docx") else None
    pdf_analysis = analyze_pdf(file_path) if file.filename.endswith(".pdf") else None

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

    save_scan_result(file.filename, verdict, yara_matches, pe_info, file_hash)
    os.remove(file_path)

    return {
        "filename": file.filename,
        "verdict": verdict,
        "risk_factors": risk_factors,
        "yara_matches": yara_matches,
        "pe_info": pe_info,
        "file_hash": file_hash
    }
