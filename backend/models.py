from sqlalchemy import Column, String, Integer, JSON, create_engine, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Database Configuration (SQLite)
DATABASE_URL = "sqlite:///scans.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Session Factory
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Base Class for ORM Models
Base = declarative_base()

# Define ScanResult Model
class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    verdict = Column(String)
    yara_matches = Column(JSON)  # Store YARA matches as JSON
    pe_info = Column(JSON)  # Store PE file details as JSON
    file_hash = Column(String, unique=True, index=True)
    timestamp = Column(TIMESTAMP, server_default=func.current_timestamp())  # Auto-Timestamp

# Create Database Tables (Ensure Tables Exist)
Base.metadata.create_all(bind=engine)

# Dependency to Get Database Session (for FastAPI)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Save Scan Result Function
def save_scan_result(db: Session, scan_data: dict):
    """Save scan results to the database, avoiding duplicate file hash entries."""
    existing_entry = db.query(ScanResult).filter(ScanResult.file_hash == scan_data["file_hash"]).first()

    if existing_entry:
        return existing_entry  # If hash already exists, return the existing entry

    new_scan = ScanResult(
        filename=scan_data["filename"],
        verdict=scan_data["verdict"],
        yara_matches=scan_data["yara_matches"],
        pe_info=scan_data["pe_info"],
        file_hash=scan_data["file_hash"],
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    return new_scan  # Return saved record
