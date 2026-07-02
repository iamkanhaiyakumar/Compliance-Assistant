import hashlib
import sqlite3
import json
import datetime
import os

# Database Path for Caching
DB_PATH = "scan_cache.db"
AUDIT_LOG_PATH = "compliance_audit.log"

# ---------------------------------------------------------
# SQLite Cache Database Setup
# ---------------------------------------------------------
def init_cache_db():
    """Initializes the cache database table with raw_bytes support."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            file_hash TEXT PRIMARY KEY,
            file_name TEXT,
            text_content TEXT,
            findings_json TEXT,
            risk_score REAL,
            risk_level TEXT,
            raw_bytes BLOB,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_cache_db()

# ---------------------------------------------------------
# SHA-256 Hashing
# ---------------------------------------------------------
def get_file_hash(file_bytes: bytes) -> str:
    """Computes SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()

# ---------------------------------------------------------
# Caching Operations
# ---------------------------------------------------------
def get_cached_scan(file_hash: str) -> dict | None:
    """Retrieves cached scan findings and raw bytes if present."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_name, text_content, findings_json, risk_score, risk_level, raw_bytes FROM scan_cache WHERE file_hash = ?",
        (file_hash,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "file_name": row[0],
            "text_content": row[1],
            "findings": json.loads(row[2]),
            "risk_score": row[3],
            "risk_level": row[4],
            "raw_bytes": row[5]
        }
    return None

def cache_scan(file_hash: str, file_name: str, text_content: str, findings: list[dict], risk_score: float, risk_level: str, raw_bytes: bytes):
    """Saves scan results and raw binary bytes to SQLite cache database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.utcnow().isoformat()
    try:
        cursor.execute(
            "INSERT OR REPLACE INTO scan_cache (file_hash, file_name, text_content, findings_json, risk_score, risk_level, raw_bytes, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file_hash, file_name, text_content, json.dumps(findings), risk_score, risk_level, raw_bytes, timestamp)
        )
        conn.commit()
    except Exception as e:
        pass # fail silently so it doesn't interrupt application flow
    finally:
        conn.close()

# ---------------------------------------------------------
# Secure JSON Audit Logger
# ---------------------------------------------------------
def log_audit_event(
    action: str,
    file_name: str,
    file_hash: str,
    risk_score: float | str,
    risk_level: str,
    duration_ms: int,
    user_id: str = "admin_01",
    ip_addr: str = "127.0.0.1"
):
    """
    Appends a secure JSON record of compliance/scanning activities to a local audit log file.
    No plaintext sensitive values are ever recorded.
    """
    log_record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "user_id": user_id,
        "client_ip": ip_addr,
        "action": action,
        "file_name": file_name,
        "file_hash": file_hash,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_duration_ms": duration_ms
    }
    
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(log_record) + "\n")
    except Exception:
        pass
        
def get_audit_logs() -> list[dict]:
    """Reads and parses the secure JSON compliance log file."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
        
    logs = []
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    logs.append(json.loads(line_str))
    except Exception:
        pass
    # Return reverse chronological order (newest logs first)
    return list(reversed(logs))
