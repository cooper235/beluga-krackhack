import os
import re
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from models import save_scan_result, get_db
from scanner import scan_file_content

# Initialize FastAPI
app = FastAPI()

# Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Allowed File Types & Limits
ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.get("/")
def read_root():
    return {"message": "Welcome to the Malware Analysis API!"}

@app.post("/scan/")
@limiter.limit("5/minute")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Handle file uploads and scan for malware indicators in-memory."""
    
    # Validate file extension
    if not any(file.filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Invalid file type.")
    
    # Read file contents
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (Max: 5MB).")
    
    # Sanitize filename
    sanitized_filename = re.sub(r"[^\w\.-]", "_", file.filename)

    # Perform static analysis (YARA, PE, Macro, PDF checks)
    scan_result = scan_file_content(contents, sanitized_filename)

    # Save scan results to database
    saved_result = save_scan_result(db, scan_result)

    return JSONResponse(content=scan_result)

