import sqlite3

# Initialize SQLite database
conn = sqlite3.connect("scans.db", check_same_thread=False)
cursor = conn.cursor()

# Create table for storing scan results
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

def save_scan_result(filename, verdict, yara_matches, pe_info, file_hash):
    """Save scan results to the database."""
    cursor.execute("""
        INSERT INTO scans (filename, verdict, yara_matches, pe_info, file_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (filename, verdict, str(yara_matches), str(pe_info), file_hash))
    conn.commit()

