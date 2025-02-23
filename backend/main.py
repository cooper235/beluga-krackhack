import os
import re
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware  # ✅ CORS Support
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from models import save_scan_result, get_scan_results, get_db  # ✅ Added function to fetch scan history
from scanner import scan_file_content

# Initialize FastAPI
app = FastAPI()

# ✅ Allow frontend connections (Replace with actual frontend URL in production)
origins = [
    "http://localhost:3000",  # React Dev Server
    "http://localhost:4200",  # Angular Dev Server
    "http://localhost:8080",  # Vue Dev Server
    "https://your-frontend-domain.com"  # Production frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# ✅ Allowed File Types & Limits
ALLOWED_EXTENSIONS = {".exe", ".pdf", ".docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.get("/")
def read_root():
    return {"message": "Welcome to the Malware Analysis API!"}

@app.post("/scan/")
@limiter.limit("5/minute")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Handle file uploads and scan for malware indicators in-memory."""
    
    # ✅ Validate file extension
    if not any(file.filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .exe, .pdf, .docx allowed.")
    
    # ✅ Read file contents
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (Max: 5MB).")
    
    # ✅ Sanitize filename
    sanitized_filename = re.sub(r"[^\w\.-]", "_", file.filename)

    # ✅ Perform static analysis (YARA, PE, Macro, PDF checks)
    scan_result = scan_file_content(contents, sanitized_filename)

    # ✅ Save scan results to database
    if db:
        try:
            save_scan_result(db, scan_result)
        except Exception as e:
            print(f"⚠️ Database save error: {e}")

    return JSONResponse(content={"status": "success", "data": scan_result})

@app.get("/scan-results/")
async def get_previous_scans(db: Session = Depends(get_db)):
    """Fetch past scan results (Optional: Useful for frontend history page)."""
    results = get_scan_results(db)
    return JSONResponse(content={"status": "success", "data": results})
