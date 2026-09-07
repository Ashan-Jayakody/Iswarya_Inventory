import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import socket
import datetime
import io
import csv
import os
import sys
import secrets
import hashlib
import hmac
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Form, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

load_dotenv()

app = FastAPI(title="Hospital Asset Barcode & QR Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# 1. Local Network IP & Port Detection
# ---------------------------------------------------------
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def find_available_port(start_port: int = 8000) -> int:
    for port in range(start_port, start_port + 20):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    return start_port

LOCAL_IP = get_local_ip()
PORT = find_available_port(8000)
SERVER_URL = f"http://{LOCAL_IP}:{PORT}"

# ---------------------------------------------------------
# 2. Database Connection & Initialization (PostgreSQL)
# ---------------------------------------------------------
DB_HOST = os.getenv("POSTGRES_HOST") or "localhost"
port_env = os.getenv("POSTGRES_PORT")
try:
    DB_PORT = int(port_env) if port_env and port_env.strip() else 5432
except (ValueError, TypeError):
    DB_PORT = 5432
DB_NAME = os.getenv("POSTGRES_DB") or "hospital_assets"
DB_USER = os.getenv("POSTGRES_USER") or "postgres"
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD") or "postgrespassword"
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or os.getenv("POSTGRES_URL_NON_POOLING")

def get_db_connection():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

def init_db():
    try:
        conn = get_db_connection()
    except Exception as e:
        err_str = str(e)
        if "does not exist" in err_str:
            try:
                conn_admin = psycopg2.connect(
                    host=DB_HOST,
                    port=DB_PORT,
                    dbname="postgres",
                    user=DB_USER,
                    password=DB_PASSWORD
                )
                conn_admin.autocommit = True
                cursor_admin = conn_admin.cursor()
                cursor_admin.execute(f'CREATE DATABASE "{DB_NAME}"')
                cursor_admin.close()
                conn_admin.close()
                conn = get_db_connection()
            except Exception as admin_err:
                print(f"Warning: Could not auto-create PostgreSQL database '{DB_NAME}': {admin_err}")
                return
        else:
            print(f"Warning: PostgreSQL connection warning: {e}")
            return

    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(255) NOT NULL,
                department VARCHAR(255) NOT NULL,
                location VARCHAR(255) NOT NULL,
                status VARCHAR(255) NOT NULL,
                serial_number VARCHAR(255),
                notes TEXT,
                created_by VARCHAR(255) DEFAULT 'System',
                updated_by VARCHAR(255) DEFAULT 'System',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS serial_number VARCHAR(255)")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS notes TEXT")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS created_by VARCHAR(255) DEFAULT 'System'")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255) DEFAULT 'System'")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(255) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                role VARCHAR(50) DEFAULT 'staff',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(255) PRIMARY KEY,
                username VARCHAR(255) REFERENCES users(username) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as err:
        print(f"Database init error: {err}")

try:
    init_db()
except Exception as e:
    print(f"PostgreSQL connection on startup skipped/failed: {e}")

# ---------------------------------------------------------
# 3. Security Helpers, Pydantic Models & API Routes
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, key_hex = stored_hash.split('$')
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

def get_current_user_from_header(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        return None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.username, u.full_name, u.role 
            FROM sessions s 
            JOIN users u ON s.username = u.username 
            WHERE s.token = %s
        """, (token,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return dict(user) if user else None
    except Exception:
        return None

class RegisterModel(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""

class LoginModel(BaseModel):
    username: str
    password: str

class AssetModel(BaseModel):
    asset_id: str = Field(..., description="Barcode or QR Code ID")
    name: str
    category: str
    department: str
    location: str
    status: str
    serial_number: Optional[str] = ""
    notes: Optional[str] = ""
    created_by: Optional[str] = "System"
    updated_by: Optional[str] = "System"

class AssetUpdateModel(BaseModel):
    name: str
    category: str
    department: str
    location: str
    status: str
    serial_number: Optional[str] = ""
    notes: Optional[str] = ""
    updated_by: Optional[str] = "System"

@app.get("/api/network-info")
def get_network_info():
    return {"local_ip": LOCAL_IP, "port": PORT, "server_url": SERVER_URL}

@app.post("/api/register")
def register_user(user_data: RegisterModel):
    username = user_data.username.strip()
    password = user_data.password.strip()
    full_name = user_data.full_name.strip() if user_data.full_name else username
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
    
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_letter and has_digit):
        raise HTTPException(status_code=400, detail="Password must be alphanumeric (contain both letters and numbers)")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username ILIKE %s", (username,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    role = "admin" if count == 0 else "staff"
    
    pwd_hash = hash_password(password)
    cursor.execute("""
        INSERT INTO users (username, password_hash, full_name, role)
        VALUES (%s, %s, %s, %s)
    """, (username, pwd_hash, full_name, role))
    
    token = secrets.token_urlsafe(32)
    cursor.execute("INSERT INTO sessions (token, username) VALUES (%s, %s)", (token, username))
    
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Account created successfully", "token": token, "username": username, "full_name": full_name, "role": role}

@app.post("/api/login")
def login_user(credentials: LoginModel):
    username = credentials.username.strip()
    password = credentials.password.strip()
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE username ILIKE %s", (username,))
    user = cursor.fetchone()
    
    if not user or not verify_password(password, user["password_hash"]):
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    token = secrets.token_urlsafe(32)
    cursor.execute("INSERT INTO sessions (token, username) VALUES (%s, %s)", (token, user["username"]))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Logged in successfully", "token": token, "username": user["username"], "full_name": user["full_name"], "role": user["role"]}

@app.get("/api/me")
def get_me(authorization: Optional[str] = Header(None)):
    user = get_current_user_from_header(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@app.post("/api/logout")
def logout_user(authorization: Optional[str] = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        cursor.close()
        conn.close()
    return {"message": "Logged out successfully"}

@app.get("/api/assets")
def list_assets(search: Optional[str] = Query(None), department: Optional[str] = Query(None), status: Optional[str] = Query(None)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    query = "SELECT * FROM assets WHERE 1=1"
    params = []
    if search:
        query += " AND (asset_id ILIKE %s OR name ILIKE %s OR location ILIKE %s OR serial_number ILIKE %s OR created_by ILIKE %s)"
        term = f"%{search}%"
        params.extend([term, term, term, term, term])
    if department:
        query += " AND department = %s"
        params.append(department)
    if status:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY updated_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: str):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM assets WHERE asset_id = %s", (asset_id.strip(),))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        return dict(row)
    raise HTTPException(status_code=404, detail="Asset not found")

@app.post("/api/assets")
def create_asset(asset: AssetModel, authorization: Optional[str] = Header(None)):
    user = get_current_user_from_header(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required to add items to inventory")
    creator = user["username"]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT asset_id FROM assets WHERE asset_id = %s", (asset.asset_id.strip(),))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Barcode ID already registered")
    now = datetime.datetime.now()
    cursor.execute("""
        INSERT INTO assets (asset_id, name, category, department, location, status, serial_number, notes, created_by, updated_by, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        asset.asset_id.strip(), asset.name.strip(), asset.category.strip(),
        asset.department.strip(), asset.location.strip(), asset.status.strip(),
        asset.serial_number.strip() if asset.serial_number else "",
        asset.notes.strip() if asset.notes else "", creator, creator, now, now
    ))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Asset registered successfully", "asset_id": asset.asset_id, "created_by": creator}

@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: str, asset: AssetUpdateModel, authorization: Optional[str] = Header(None)):
    user = get_current_user_from_header(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required to update inventory items")
    updater = user["username"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT asset_id FROM assets WHERE asset_id = %s", (asset_id.strip(),))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Asset not found")
    now = datetime.datetime.now()
    cursor.execute("""
        UPDATE assets 
        SET name = %s, category = %s, department = %s, location = %s, status = %s, serial_number = %s, notes = %s, updated_by = %s, updated_at = %s
        WHERE asset_id = %s
    """, (
        asset.name.strip(), asset.category.strip(), asset.department.strip(),
        asset.location.strip(), asset.status.strip(),
        asset.serial_number.strip() if asset.serial_number else "",
        asset.notes.strip() if asset.notes else "", updater, now, asset_id.strip()
    ))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Asset updated successfully", "asset_id": asset_id, "updated_by": updater}

@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user_from_header(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required to delete inventory items")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE asset_id = %s", (asset_id.strip(),))
    deleted = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    if deleted:
        return {"message": "Asset deleted successfully"}
    raise HTTPException(status_code=404, detail="Asset not found")

@app.get("/export")
def export_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT asset_id, name, category, department, location, status, serial_number, notes, created_by, updated_by, created_at, updated_at FROM assets ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["Barcode ID", "Name", "Category", "Department", "Location", "Status", "Serial Number", "Notes", "Entered By", "Last Updated By", "Created At", "Updated At"])
    writer.writerows(rows)
    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=hospital_inventory.csv"
    return response

# ---------------------------------------------------------
# 4. Barcode Web Application HTML / JS / CSS
# ---------------------------------------------------------
BARCODE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Hospital Asset Management</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

    <!-- HTML5 Barcode & QR Code Scanner Library -->
    <script src="https://unpkg.com/html5-qrcode"></script>

    <style>
        :root {
            --bg-color: #0b0f17;
            --card-bg: #111827;
            --card-border: #1f293d;
            --input-bg: #0d1322;
            --input-border: #2a374f;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --text-subtle: #64748b;
            --radius-md: 6px;
            --radius-lg: 10px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; -webkit-tap-highlight-color: transparent; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; padding-bottom: 76px; }

        header { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--card-border); padding: 12px 20px; position: sticky; top: 0; z-index: 100; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
        .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-main); }
        .brand-badge { background: rgba(59, 130, 246, 0.12); color: #60a5fa; border: 1px solid rgba(96, 165, 250, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; letter-spacing: 0.04em; }
        .ip-badge { background: #162032; color: var(--text-muted); border: 1px solid var(--card-border); padding: 5px 10px; border-radius: 6px; font-size: 0.76rem; font-weight: 500; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s ease; }
        .ip-badge strong { color: var(--text-main); font-weight: 600; }
        .ip-badge:hover { border-color: var(--accent); background: #1e293b; }

        .container { width: 100%; max-width: 860px; margin: 0 auto; padding: 20px 16px; flex: 1; }

        .tab-nav { display: flex; gap: 4px; margin-bottom: 20px; background: #0d1322; padding: 3px; border-radius: var(--radius-md); border: 1px solid var(--card-border); }
        .tab-btn { flex: 1; padding: 9px 12px; border: none; background: transparent; color: var(--text-muted); font-weight: 500; font-size: 0.85rem; border-radius: 4px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; transition: all 0.15s ease; }
        .tab-btn.active { background: var(--card-bg) !important; color: var(--text-main) !important; border: 1px solid #334155; font-weight: 600; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }

        .tab-content { display: none !important; }
        .tab-content.active { display: block !important; animation: fadeIn 0.15s ease; }

        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius-lg); padding: 20px; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); }
        .card-title { font-size: 0.92rem; font-weight: 600; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; color: var(--text-main); letter-spacing: -0.01em; }

        #reader-wrapper { position: relative; border-radius: var(--radius-md); overflow: hidden; border: 1px solid var(--card-border); background: #000; min-height: 240px; }
        #reader { width: 100%; border: none !important; }
        #reader img { display: none !important; }
        #reader video { width: 100% !important; object-fit: cover; }
        #reader__dashboard_section_csr button { padding: 8px 14px; border-radius: 6px; background: var(--card-bg); color: var(--text-main); border: 1px solid var(--card-border); font-size: 0.85rem; font-weight: 500; cursor: pointer; margin: 4px; }
        #reader__camera_selection { padding: 8px 12px; border-radius: 6px; background: var(--input-bg); color: var(--text-main); border: 1px solid var(--input-border); width: 100%; outline: none; margin-bottom: 8px; font-size: 0.88rem; }

        .scanner-actions { display: flex; gap: 10px; margin-top: 14px; }
        .btn { min-height: 42px; padding: 9px 16px; border-radius: var(--radius-md); border: 1px solid transparent; font-weight: 500; font-size: 0.86rem; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.15s ease; text-decoration: none; }
        .btn-primary { background: var(--accent); color: #ffffff; border-color: var(--accent); }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-secondary { background: #1e293b; color: var(--text-main); border-color: #334155; }
        .btn-secondary:hover { background: #334155; }
        .btn-outline { background: transparent; color: var(--text-muted); border-color: var(--card-border); }
        .btn-outline:hover { background: #1e293b; color: var(--text-main); }
        .btn-danger { background: rgba(239, 68, 68, 0.12); color: #f87171; border-color: rgba(248, 113, 113, 0.3); }
        .btn-danger:hover { background: rgba(239, 68, 68, 0.22); }

        .file-upload-btn { position: relative; overflow: hidden; width: 100%; }
        .file-upload-btn input[type=file] { position: absolute; left: 0; top: 0; opacity: 0; width: 100%; height: 100%; cursor: pointer; }

        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }
        .form-control { width: 100%; min-height: 42px; padding: 9px 12px; background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 6px; color: var(--text-main); font-size: 0.9rem; outline: none; transition: border-color 0.15s ease; }
        .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }
        select.form-control option { background-color: #111827; color: #f1f5f9; }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        @media (max-width: 600px) { .form-row { grid-template-columns: 1fr; } }

        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 500; background: #162032; border: 1px solid #2a374f; color: var(--text-main); }
        .badge-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
        .badge-dot.active { background: #10b981; }
        .badge-dot.maintenance { background: #f59e0b; }
        .badge-dot.order { background: #ef4444; }

        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.86rem; }
        th { background: #0d1322; padding: 10px 14px; color: var(--text-muted); font-weight: 600; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--card-border); }
        td { padding: 12px 14px; border-bottom: 1px solid var(--card-border); color: var(--text-main); }
        tr:hover td { background: #162032; }

        .qr-center { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; text-align: center; }

        #toast { position: fixed; bottom: 76px; left: 50%; transform: translateX(-50%); background: #1e293b; border: 1px solid #334155; color: #f8fafc; padding: 10px 20px; border-radius: 20px; font-size: 0.82rem; font-weight: 500; box-shadow: 0 8px 20px rgba(0,0,0,0.4); display: none; z-index: 2000; transition: all 0.2s ease; }

        .mobile-nav { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(17, 24, 39, 0.95); backdrop-filter: blur(12px); border-top: 1px solid var(--card-border); display: flex; justify-content: space-around; padding: 8px 0; z-index: 200; }
        .mobile-nav-btn { display: flex; flex-direction: column; align-items: center; gap: 3px; background: none; border: none; color: var(--text-muted); font-size: 0.75rem; font-weight: 500; cursor: pointer; padding: 6px 16px; border-radius: 6px; transition: color 0.15s ease; }
        .mobile-nav-btn.active { color: var(--accent); font-weight: 600; }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <span>Risky Assets</span>
            <span class="brand-badge">Inventory</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <div class="ip-badge" onclick="switchTab('pair')">
                <span>Mobile:</span>
                <strong>__LOCAL_IP__:__PORT__</strong>
            </div>
            <div id="user-header-status">
                <button class="btn btn-primary" style="padding: 5px 12px; min-height: 32px; font-size: 0.8rem;" onclick="openAuthModal('login')">Sign In</button>
            </div>
        </div>
    </header>

    <!-- AUTH MODAL -->
    <div id="auth-modal" style="display: none; position: fixed; inset: 0; background: rgba(3, 7, 18, 0.75); backdrop-filter: blur(8px); z-index: 1000; align-items: center; justify-content: center; padding: 16px;">
        <div class="card" style="width: 100%; max-width: 400px; margin: 0; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--card-border); padding-bottom: 10px;">
                <h3 id="auth-modal-title" style="font-size: 1rem; font-weight: 600; color: var(--text-main);">Sign In</h3>
                <button onclick="closeAuthModal()" style="background: none; border: none; font-size: 1.2rem; cursor: pointer; color: var(--text-muted);">&times;</button>
            </div>
            <div style="display: flex; gap: 4px; background: #0d1322; padding: 3px; border-radius: var(--radius-md); margin-bottom: 16px; border: 1px solid var(--card-border);">
                <button type="button" class="tab-btn active" id="auth-tab-login" onclick="switchAuthTab('login')">Sign In</button>
                <button type="button" class="tab-btn" id="auth-tab-register" onclick="switchAuthTab('register')">Register</button>
            </div>
            <form id="auth-form" onsubmit="handleAuthSubmit(event)">
                <div class="form-group" id="group-fullname" style="display: none;">
                    <label>Full Name</label>
                    <input type="text" id="auth-fullname" class="form-control" placeholder="e.g. Sarah Jenkins">
                </div>
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="auth-username" class="form-control" placeholder="Enter username" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="auth-password" class="form-control" placeholder="Enter password" required autocomplete="current-password">
                    <div id="password-hint" style="display: none; font-size: 0.74rem; color: var(--text-muted); margin-top: 5px;">Must be min 6 characters with letters and numbers.</div>
                </div>
                <div id="auth-error" style="display: none; color: #f87171; font-size: 0.8rem; margin-bottom: 12px; font-weight: 500;"></div>
                <button type="submit" id="auth-submit-btn" class="btn btn-primary" style="width: 100%;">Sign In</button>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="tab-nav">
            <button class="tab-btn active" id="tab-btn-scan" onclick="switchTab('scan')">Barcode Scanner</button>
            <button class="tab-btn" id="tab-btn-inventory" onclick="switchTab('inventory')">Inventory List</button>
            <button class="tab-btn" id="tab-btn-pair" onclick="switchTab('pair')">Mobile Connection</button>
        </div>

        <!-- TAB 1: SCANNER -->
        <div id="tab-scan" class="tab-content active">
            <div class="card">
                <div class="card-title">
                    <span>Camera Viewfinder</span>
                    <span class="badge"><span class="badge-dot active"></span>Camera Ready</span>
                </div>

                <div id="reader-wrapper">
                    <div id="reader"></div>
                </div>

                <div class="scanner-actions">
                    <div class="btn btn-secondary file-upload-btn">
                        <span>Upload or Capture Barcode Image</span>
                        <input type="file" id="qr-input-file" accept="image/*" capture="environment">
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Manual Barcode Input</div>
                <form onsubmit="event.preventDefault(); lookupManualId();" style="display: flex; gap: 8px;">
                    <input type="text" id="manual-asset-id" class="form-control" placeholder="Enter or scan Barcode ID..." onkeydown="if(event.key==='Enter'){event.preventDefault(); lookupManualId();}">
                    <button type="submit" class="btn btn-secondary" style="min-width: 90px;">Lookup</button>
                </form>
            </div>

            <div id="scan-result-card"></div>
        </div>

        <!-- TAB 2: INVENTORY -->
        <div id="tab-inventory" class="tab-content">
            <div class="card">
                <div class="card-title">
                    <span>Asset Inventory</span>
                    <a href="/export" class="btn btn-secondary" style="font-size: 0.8rem; min-height: 34px; padding: 4px 12px;">Export CSV</a>
                </div>

                <div class="form-row" style="margin-bottom: 16px;">
                    <input type="text" id="inv-search" class="form-control" placeholder="Search by name, ID, room, or user..." oninput="loadInventory()">
                    <select id="inv-dept-filter" class="form-control" onchange="loadInventory()">
                        <option value="">All Departments</option>
                        <option value="Admin">Admin</option>
                        <option value="Finance">Finance</option>
                        <option value="Lab">Lab</option>
                        <option value="Nursing">Nursing</option>
                        <option value="Hr">Hr</option>
                        <option value="It">It</option>
                        <option value="Reception/billing">Reception/billing</option>
                        <option value="Councelling">Councelling</option>
                        <option value="Clinical">Clinical</option>
                    </select>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Barcode ID</th>
                                <th>Name</th>
                                <th>Category</th>
                                <th>Department</th>
                                <th>Location</th>
                                <th>Status</th>
                                <th>Entered By</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="inventory-table-body">
                            <tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">Loading inventory...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: MOBILE PAIR -->
        <div id="tab-pair" class="tab-content">
            <div class="card qr-center">
                <h3 style="font-size: 1rem; font-weight: 600; margin-bottom: 6px;">Mobile Device Connection</h3>
                <p style="color: var(--text-muted); font-size: 0.85rem; max-width: 480px; line-height: 1.5;">
                    Ensure your mobile device is connected to the <strong>same network</strong> as this server, then open this address in Chrome or Safari:
                </p>

                <div style="background: #0d1322; border: 1px solid var(--card-border); padding: 14px 20px; border-radius: var(--radius-md); text-align: center; margin: 20px 0; width: 100%; max-width: 440px;">
                    <div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Mobile Server Address</div>
                    <strong id="mobile-url-display" style="font-size: 1.25rem; color: var(--accent);">__SERVER_URL__</strong>
                </div>

                <div style="text-align: left; background: #0d1322; border: 1px solid var(--card-border); padding: 16px; border-radius: var(--radius-md); font-size: 0.85rem; width: 100%; max-width: 500px; color: var(--text-muted);">
                    <strong style="color: var(--text-main); font-size: 0.88rem;">Scanning Guidelines</strong>
                    <ul style="margin-left: 18px; margin-top: 6px; line-height: 1.6;">
                        <li><strong>Photo Capture:</strong> Tap <strong>Upload or Capture Barcode Image</strong> to snap physical barcode tags using your device camera.</li>
                        <li><strong>Feedback:</strong> System emits a clean audio tone and haptic vibration upon successful decode.</li>
                        <li><strong>Supported Formats:</strong> CODE128, CODE39, CODE93, EAN-13, EAN-8, UPC-A, UPC-E, Codabar, and QR Codes.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <div class="mobile-nav">
        <button class="mobile-nav-btn active" id="mob-btn-scan" onclick="switchTab('scan')">
            <span>Scanner</span>
        </button>
        <button class="mobile-nav-btn" id="mob-btn-inventory" onclick="switchTab('inventory')">
            <span>Inventory</span>
        </button>
        <button class="mobile-nav-btn" id="mob-btn-pair" onclick="switchTab('pair')">
            <span>Connection</span>
        </button>
    </div>

    <div id="toast">Notification</div>

    <script>
        const SERVER_URL = window.location.origin;
        let html5QrcodeScanner = null;
        let authMode = 'login';
        let currentUser = null;

        function getAuthHeaders() {
            const token = localStorage.getItem('auth_token');
            const headers = { 'Content-Type': 'application/json' };
            if (token) {
                headers['Authorization'] = 'Bearer ' + token;
            }
            return headers;
        }

        async function checkAuthOnLoad() {
            const token = localStorage.getItem('auth_token');
            if (!token) {
                updateUserHeaderUI(null);
                return;
            }
            try {
                const res = await fetch('/api/me', { headers: getAuthHeaders() });
                if (res.ok) {
                    currentUser = await res.json();
                    updateUserHeaderUI(currentUser);
                } else {
                    localStorage.removeItem('auth_token');
                    currentUser = null;
                    updateUserHeaderUI(null);
                }
            } catch (e) {
                console.error("Auth check failed:", e);
            }
        }

        function updateUserHeaderUI(user) {
            const container = document.getElementById('user-header-status');
            if (!container) return;
            if (user) {
                container.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa; border-color: rgba(96, 165, 250, 0.3); font-weight: 600;">
                            ${user.username}
                        </span>
                        <button class="btn btn-outline" style="padding: 3px 8px; min-height: 28px; font-size: 0.76rem;" onclick="logoutUser()">Sign Out</button>
                    </div>
                `;
            } else {
                container.innerHTML = `
                    <button class="btn btn-primary" style="padding: 5px 12px; min-height: 32px; font-size: 0.8rem;" onclick="openAuthModal('login')">Sign In</button>
                `;
            }
        }

        function openAuthModal(mode = 'login') {
            switchAuthTab(mode);
            document.getElementById('auth-modal').style.display = 'flex';
        }

        function closeAuthModal() {
            document.getElementById('auth-modal').style.display = 'none';
            document.getElementById('auth-error').style.display = 'none';
        }

        function switchAuthTab(mode) {
            authMode = mode;
            document.getElementById('auth-error').style.display = 'none';
            const hint = document.getElementById('password-hint');
            if (mode === 'login') {
                document.getElementById('auth-tab-login').classList.add('active');
                document.getElementById('auth-tab-register').classList.remove('active');
                document.getElementById('group-fullname').style.display = 'none';
                if (hint) hint.style.display = 'none';
                document.getElementById('auth-modal-title').innerText = 'Sign In';
                document.getElementById('auth-submit-btn').innerText = 'Sign In';
            } else {
                document.getElementById('auth-tab-register').classList.add('active');
                document.getElementById('auth-tab-login').classList.remove('active');
                document.getElementById('group-fullname').style.display = 'block';
                if (hint) hint.style.display = 'block';
                document.getElementById('auth-modal-title').innerText = 'Register Account';
                document.getElementById('auth-submit-btn').innerText = 'Create Account';
            }
        }

        async function handleAuthSubmit(e) {
            e.preventDefault();
            const username = document.getElementById('auth-username').value.trim();
            const password = document.getElementById('auth-password').value.trim();
            const fullName = document.getElementById('auth-fullname').value.trim();
            const errEl = document.getElementById('auth-error');
            errEl.style.display = 'none';

            if (authMode === 'register') {
                const hasLetter = /[a-zA-Z]/.test(password);
                const hasDigit = /[0-9]/.test(password);
                if (password.length < 6 || !hasLetter || !hasDigit) {
                    errEl.innerText = "Password must be at least 6 characters long and contain both letters and numbers";
                    errEl.style.display = 'block';
                    return;
                }
            }

            const endpoint = authMode === 'login' ? '/api/login' : '/api/register';
            const body = authMode === 'login' 
                ? { username, password } 
                : { username, password, full_name: fullName || username };

            try {
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (res.ok) {
                    localStorage.setItem('auth_token', data.token);
                    currentUser = { username: data.username, full_name: data.full_name, role: data.role };
                    updateUserHeaderUI(currentUser);
                    closeAuthModal();
                    showToast(authMode === 'login' ? "Signed in successfully!" : "Account created!");
                } else {
                    errEl.innerText = data.detail || "Authentication failed";
                    errEl.style.display = 'block';
                }
            } catch (err) {
                errEl.innerText = "Network error";
                errEl.style.display = 'block';
            }
        }

        async function logoutUser() {
            try {
                await fetch('/api/logout', { method: 'POST', headers: getAuthHeaders() });
            } catch (e) {}
            localStorage.removeItem('auth_token');
            currentUser = null;
            updateUserHeaderUI(null);
            showToast("Signed out");
        }

        function playScanBeep() {
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(987.77, ctx.currentTime);
                gain.gain.setValueAtTime(0.12, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.12);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.12);
            } catch(e) {}
        }

        function triggerHaptic() {
            if (navigator.vibrate) {
                try { navigator.vibrate(60); } catch(e) {}
            }
        }

        function getStatusBadgeHtml(status) {
            let dotClass = "active";
            if(status === 'Repair required') dotClass = "maintenance";
            if(status === 'Damaged' || status === 'Disposable') dotClass = "order";
            return `<span class="badge"><span class="badge-dot ${dotClass}"></span>${status}</span>`;
        }

        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.mobile-nav-btn').forEach(btn => btn.classList.remove('active'));

            const targetContent = document.getElementById('tab-' + tabName);
            if(targetContent) targetContent.classList.add('active');

            const targetDesktopBtn = document.getElementById('tab-btn-' + tabName);
            if(targetDesktopBtn) targetDesktopBtn.classList.add('active');

            const targetMobileBtn = document.getElementById('mob-btn-' + tabName);
            if(targetMobileBtn) targetMobileBtn.classList.add('active');

            if(tabName === 'inventory') loadInventory();
        }

        window.addEventListener('DOMContentLoaded', () => {
            const urlEl = document.getElementById('mobile-url-display');
            if(urlEl) urlEl.innerText = window.location.origin;
            checkAuthOnLoad();
            try { startBarcodeScanner(); } catch(e) {}
            try { loadInventory(); } catch(e) {}
        });

        function startBarcodeScanner() {
            if (typeof Html5QrcodeScanner === 'undefined') {
                console.error("html5-qrcode library not loaded.");
                return;
            }

            if (html5QrcodeScanner) {
                try {
                    html5QrcodeScanner.clear();
                } catch (e) {
                    console.warn("Could not clear previous scanner:", e);
                }
                html5QrcodeScanner = null;
            }

            try {
                html5QrcodeScanner = new Html5QrcodeScanner(
                    "reader",
                    {
                        fps: 8,

                        qrbox: function(viewfinderWidth, viewfinderHeight) {
                            const width = Math.min(viewfinderWidth * 0.90, 500);
                            const height = Math.min(160, viewfinderHeight * 0.45);

                            return {
                                width: Math.floor(width),
                                height: Math.floor(height)
                            };
                        },

                        formatsToSupport: [
                            Html5QrcodeSupportedFormats.CODE_128,
                            Html5QrcodeSupportedFormats.CODE_39,
                            Html5QrcodeSupportedFormats.CODE_93,
                            Html5QrcodeSupportedFormats.EAN_13,
                            Html5QrcodeSupportedFormats.EAN_8,
                            Html5QrcodeSupportedFormats.UPC_A,
                            Html5QrcodeSupportedFormats.UPC_E,
                            Html5QrcodeSupportedFormats.CODABAR,
                            Html5QrcodeSupportedFormats.QR_CODE
                        ],

                        useBarCodeDetectorIfSupported: false,
                        rememberLastUsedCamera: true,
                        showTorchButtonIfSupported: true,
                        showZoomSliderIfSupported: true,
                        defaultZoomValueIfSupported: 2
                    },
                    false
                );

                html5QrcodeScanner.render(
                    onScanSuccess,
                    onScanError
                );

            } catch (err) {
                console.error("Barcode scanner initialization error:", err);
            }
        }

        function onScanSuccess(decodedText) {
            playScanBeep();
            triggerHaptic();
            showToast("Barcode Scanned: " + decodedText);
            handleScannedId(decodedText);
        }

        function onScanError(error) {}

        const fileInput = document.getElementById('qr-input-file');
        if (fileInput) {
            fileInput.addEventListener('change', e => {
                if (!e.target.files || e.target.files.length === 0) return;
                const imageFile = e.target.files[0];

                if (typeof Html5Qrcode === 'undefined') return alert("Scanner not ready.");

                const html5QrCode = new Html5Qrcode("reader");
                html5QrCode.scanFile(imageFile, true)
                    .then(decodedText => {
                        playScanBeep();
                        triggerHaptic();
                        showToast("Barcode Decoded: " + decodedText);
                        handleScannedId(decodedText);
                    })
                    .catch(err => {
                        alert("Could not read a clear barcode from this photo. Ensure good lighting and try again.");
                    });
            });
        }

        function lookupManualId() {
            const val = document.getElementById('manual-asset-id').value.trim();
            if(!val) return alert("Please enter a Barcode ID");
            handleScannedId(val);
        }

        async function handleScannedId(assetId) {
            const resCard = document.getElementById('scan-result-card');
            resCard.innerHTML = `
                <div class="card" style="text-align: center; padding: 24px;">
                    <div style="font-size: 0.9rem; color: var(--text-muted);">Searching Barcode: <strong style="color: var(--text-main);">${assetId}</strong>...</div>
                </div>`;

            try {
                const res = await fetch('/api/assets/' + encodeURIComponent(assetId));
                if(res.ok) {
                    const asset = await res.json();
                    renderExistingAssetCard(asset);
                } else {
                    renderNewAssetForm(assetId);
                }
            } catch(err) {
                alert("Network error communicating with server.");
            }
        }

        function renderExistingAssetCard(asset) {
            const resCard = document.getElementById('scan-result-card');
            const formattedDate = asset.updated_at ? new Date(asset.updated_at).toLocaleString() : 'Just now';

            resCard.innerHTML = `
                <div class="card">
                    <div class="card-title" style="border-bottom: 1px solid var(--card-border); padding-bottom: 10px; margin-bottom: 14px;">
                        <div>
                            <span style="font-size: 1.05rem; font-weight: 600; color: var(--text-main);">${asset.name}</span>
                            <div style="font-size: 0.8rem; color: var(--accent); font-weight: 500; margin-top: 2px;">Barcode ID: ${asset.asset_id}</div>
                        </div>
                        ${getStatusBadgeHtml(asset.status)}
                    </div>

                    <div style="background: #0d1322; border: 1px solid var(--card-border); border-radius: 6px; padding: 14px; margin-bottom: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.88rem;">
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">CATEGORY</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.category || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">DEPARTMENT</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.department || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">LOCATION</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.location || 'Unspecified'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">STATUS</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.status}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">ENTERED BY</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.created_by || 'System'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">LAST UPDATED BY</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.updated_by || 'System'}</div>
                        </div>
                        ${asset.serial_number ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">SERIAL / MODEL</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.serial_number}</div>
                        </div>` : ''}
                        ${asset.notes ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">NOTES</div>
                            <div style="font-weight: 400; color: var(--text-muted); margin-top: 2px;">${asset.notes}</div>
                        </div>` : ''}
                        <div style="grid-column: span 2; border-top: 1px solid var(--card-border); padding-top: 8px; font-size: 0.74rem; color: var(--text-subtle);">
                            Last Updated: ${formattedDate}
                        </div>
                    </div>

                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-secondary" style="flex: 1;" onclick="toggleEditForm()">Edit Details</button>
                        <button class="btn btn-primary" onclick="document.getElementById('scan-result-card').innerHTML=''">Scan Another</button>
                    </div>

                    <form id="edit-asset-form" style="display: none; margin-top: 16px; border-top: 1px solid var(--card-border); padding-top: 16px;" onsubmit="submitAssetUpdate(event, '${asset.asset_id}')">
                        <h4 style="margin-bottom: 12px; font-size: 0.9rem; font-weight: 600; color: var(--text-main);">Edit Asset Details</h4>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label>Asset Name</label>
                                <input type="text" id="edit-name" class="form-control" value="${asset.name}" required>
                            </div>
                            <div class="form-group">
                                <label>Status</label>
                                <select id="edit-status" class="form-control">
                                    <option value="Active" ${asset.status === 'Active' ? 'selected' : ''}>Active</option>
                                    <option value="Damaged" ${asset.status === 'Damaged' ? 'selected' : ''}>Damaged</option>
                                    <option value="Disposable" ${asset.status === 'Disposable' ? 'selected' : ''}>Disposable</option>
                                    <option value="Repair required" ${asset.status === 'Repair required' ? 'selected' : ''}>Repair required</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Category</label>
                                <select id="edit-category" class="form-control">
                                    <option value="Medical & Surgical Equipment" ${asset.category === 'Medical & Surgical Equipment' ? 'selected' : ''}>Medical & Surgical Equipment</option>
                                    <option value="Office equipment" ${asset.category === 'Office equipment' ? 'selected' : ''}>Office equipment</option>
                                    <option value="IT equipment" ${asset.category === 'IT equipment' ? 'selected' : ''}>IT equipment</option>
                                    <option value="Furniture & fixtures" ${asset.category === 'Furniture & fixtures' ? 'selected' : ''}>Furniture & fixtures</option>
                                    <option value="Intangible assets" ${asset.category === 'Intangible assets' ? 'selected' : ''}>Intangible assets</option>
                                    <option value="Other equipment" ${asset.category === 'Other equipment' ? 'selected' : ''}>Other equipment</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Department</label>
                                <select id="edit-dept" class="form-control">
                                    <option value="Admin" ${asset.department === 'Admin' ? 'selected' : ''}>Admin</option>
                                    <option value="Finance" ${asset.department === 'Finance' ? 'selected' : ''}>Finance</option>
                                    <option value="Lab" ${asset.department === 'Lab' ? 'selected' : ''}>Lab</option>
                                    <option value="Nursing" ${asset.department === 'Nursing' ? 'selected' : ''}>Nursing</option>
                                    <option value="Hr" ${asset.department === 'Hr' ? 'selected' : ''}>Hr</option>
                                    <option value="It" ${asset.department === 'It' ? 'selected' : ''}>It</option>
                                    <option value="Reception/billing" ${asset.department === 'Reception/billing' ? 'selected' : ''}>Reception/billing</option>
                                    <option value="Councelling" ${asset.department === 'Councelling' ? 'selected' : ''}>Councelling</option>
                                    <option value="Clinical" ${asset.department === 'Clinical' ? 'selected' : ''}>Clinical</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Location / Room</label>
                                <input type="text" id="edit-location" class="form-control" value="${asset.location}" required>
                            </div>
                            <div class="form-group">
                                <label>Serial Number</label>
                                <input type="text" id="edit-serial" class="form-control" value="${asset.serial_number || ''}">
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Notes</label>
                            <input type="text" id="edit-notes" class="form-control" value="${asset.notes || ''}">
                        </div>

                        <div style="display: flex; gap: 10px; margin-top: 12px;">
                            <button type="submit" class="btn btn-primary" style="flex: 1;">Save Changes</button>
                            <button type="button" class="btn btn-secondary" onclick="toggleEditForm()">Cancel</button>
                        </div>
                    </form>
                </div>`;
            
            resCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function toggleEditForm() {
            const form = document.getElementById('edit-asset-form');
            if(form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
        }

        function renderNewAssetForm(assetId) {
            const resCard = document.getElementById('scan-result-card');
            const authNotice = !currentUser ? `
                <div style="background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(96, 165, 250, 0.3); border-radius: var(--radius-md); padding: 12px 14px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; gap: 10px; font-size: 0.84rem; color: #93c5fd;">
                    <span><strong>Sign in required</strong> to register items into inventory.</span>
                    <button type="button" class="btn btn-primary" style="padding: 4px 12px; min-height: 32px; font-size: 0.8rem;" onclick="openAuthModal('login')">Sign In</button>
                </div>
            ` : `<div style="font-size: 0.8rem; color: var(--accent); margin-bottom: 12px; font-weight: 500;">Signing as: <strong>${currentUser.username}</strong></div>`;

            resCard.innerHTML = `
                <div class="card">
                    <div class="card-title">
                        <span>Register New Asset</span>
                        <span class="badge"><span class="badge-dot maintenance"></span>New Barcode</span>
                    </div>
                    ${authNotice}
                    <form id="new-asset-form" onsubmit="submitNewAsset(event)">
                        <div class="form-group">
                            <label>Scanned Barcode ID</label>
                            <input type="text" id="new-id" class="form-control" value="${assetId}" readonly style="background: #0d1322; font-weight: 600; color: #60a5fa;">
                        </div>`

                        <div class="form-group">
                            <label>Asset Name</label>
                            <input type="text" id="new-name" class="form-control" placeholder="e.g. Patient Monitor X200" required>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Category</label>
                                <select id="new-category" class="form-control">
                                    <option value="Medical & Surgical Equipment">Medical & Surgical Equipment</option>
                                    <option value="Office equipment">Office equipment</option>
                                    <option value="IT equipment">IT equipment</option>
                                    <option value="Furniture & fixtures">Furniture & fixtures</option>
                                    <option value="Intangible assets">Intangible assets</option>
                                    <option value="Other equipment">Other equipment</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Department</label>
                                <select id="new-department" class="form-control">
                                    <option value="Admin">Admin</option>
                                    <option value="Finance">Finance</option>
                                    <option value="Lab">Lab</option>
                                    <option value="Nursing">Nursing</option>
                                    <option value="Hr">Hr</option>
                                    <option value="It">It</option>
                                    <option value="Reception/billing">Reception/billing</option>
                                    <option value="Councelling">Councelling</option>
                                    <option value="Clinical">Clinical</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Location / Room</label>
                                <input type="text" id="new-location" class="form-control" placeholder="e.g. Room 304, Bed 2" required>
                            </div>
                            <div class="form-group">
                                <label>Status</label>
                                <select id="new-status" class="form-control">
                                    <option value="Active">Active</option>
                                    <option value="Damaged">Damaged</option>
                                    <option value="Disposable">Disposable</option>
                                    <option value="Repair required">Repair required</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Serial Number (Optional)</label>
                                <input type="text" id="new-serial" class="form-control" placeholder="e.g. SN-8839201">
                            </div>
                            <div class="form-group">
                                <label>Notes (Optional)</label>
                                <input type="text" id="new-notes" class="form-control" placeholder="e.g. Calibration due Oct 2026">
                            </div>
                        </div>

                        <div style="display: flex; gap: 10px; margin-top: 14px;">
                            <button type="submit" class="btn btn-primary" style="flex: 1;">Save Asset to Database</button>
                            <button type="button" class="btn btn-secondary" onclick="document.getElementById('scan-result-card').innerHTML=''">Cancel</button>
                        </div>
                    </form>
                </div>`;

            resCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        async function submitNewAsset(e) {
            e.preventDefault();
            if (!currentUser) {
                openAuthModal('login');
                showToast("Please sign in to add items to inventory");
                return;
            }
            const payload = {
                asset_id: document.getElementById('new-id').value,
                name: document.getElementById('new-name').value,
                category: document.getElementById('new-category').value,
                department: document.getElementById('new-department').value,
                location: document.getElementById('new-location').value,
                status: document.getElementById('new-status').value,
                serial_number: document.getElementById('new-serial').value,
                notes: document.getElementById('new-notes').value
            };

            const res = await fetch('/api/assets', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(payload)
            });

            if(res.ok) {
                showToast("Asset Saved Successfully!");
                handleScannedId(payload.asset_id);
            } else {
                if (res.status === 401) {
                    localStorage.removeItem('auth_token');
                    currentUser = null;
                    updateUserHeaderUI(null);
                    openAuthModal('login');
                    showToast("Please sign in to add items to inventory");
                    return;
                }
                const data = await res.json();
                alert("Error saving asset: " + (data.detail || "Failed"));
            }
        }

        async function submitAssetUpdate(e, assetId) {
            e.preventDefault();
            if (!currentUser) {
                openAuthModal('login');
                showToast("Please sign in to update items");
                return;
            }
            const payload = {
                name: document.getElementById('edit-name').value,
                category: document.getElementById('edit-category').value,
                department: document.getElementById('edit-dept').value,
                location: document.getElementById('edit-location').value,
                status: document.getElementById('edit-status').value,
                serial_number: document.getElementById('edit-serial').value,
                notes: document.getElementById('edit-notes').value
            };

            const res = await fetch('/api/assets/' + encodeURIComponent(assetId), {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify(payload)
            });

            if(res.ok) {
                showToast("Asset Updated!");
                handleScannedId(assetId);
            } else {
                if (res.status === 401) {
                    localStorage.removeItem('auth_token');
                    currentUser = null;
                    updateUserHeaderUI(null);
                    openAuthModal('login');
                    showToast("Please sign in to update items");
                    return;
                }
                alert("Failed to update asset.");
            }
        }

        async function loadInventory() {
            const searchEl = document.getElementById('inv-search');
            const deptEl = document.getElementById('inv-dept-filter');
            const search = searchEl ? searchEl.value : '';
            const dept = deptEl ? deptEl.value : '';

            let url = '/api/assets?';
            if(search) url += 'search=' + encodeURIComponent(search) + '&';
            if(dept) url += 'department=' + encodeURIComponent(dept);

            try {
                const res = await fetch(url);
                const assets = await res.json();
                const tbody = document.getElementById('inventory-table-body');
                if(!tbody) return;
                
                if(!assets || assets.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No assets registered yet. Scan a barcode to add one.</td></tr>';
                    return;
                }

                tbody.innerHTML = assets.map(a => {
                    return `
                        <tr>
                            <td><strong style="color: var(--accent);">${a.asset_id}</strong></td>
                            <td><strong>${a.name}</strong></td>
                            <td>${a.category}</td>
                            <td>${a.department}</td>
                            <td>${a.location}</td>
                            <td>${getStatusBadgeHtml(a.status)}</td>
                            <td><span style="font-size: 0.8rem; color: var(--text-muted);">${a.created_by || 'System'}</span></td>
                            <td>
                                <button class="btn btn-secondary" style="padding: 4px 10px; min-height: 30px; font-size: 0.78rem;" onclick="switchTab('scan'); handleScannedId('${a.asset_id}');">Edit</button>
                                <button class="btn btn-danger" style="padding: 4px 10px; min-height: 30px; font-size: 0.78rem;" onclick="deleteAsset('${a.asset_id}')">Delete</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch(err) {
                console.error("Inventory error:", err);
            }
        }

        async function deleteAsset(assetId) {
            if (!currentUser) {
                openAuthModal('login');
                showToast("Please sign in to delete inventory items");
                return;
            }
            if(!confirm("Are you sure you want to delete barcode " + assetId + " from database?")) return;
            const res = await fetch('/api/assets/' + encodeURIComponent(assetId), { 
                method: 'DELETE',
                headers: getAuthHeaders()
            });
            if(res.ok) {
                showToast("Asset deleted");
                loadInventory();
            } else if (res.status === 401) {
                localStorage.removeItem('auth_token');
                currentUser = null;
                updateUserHeaderUI(null);
                openAuthModal('login');
                showToast("Please sign in to delete inventory items");
            }
        }

        function showToast(msg) {
            const toast = document.getElementById('toast');
            if(!toast) return;
            toast.innerText = msg;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 3000);
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root():
    content = BARCODE_HTML.replace("__LOCAL_IP__", LOCAL_IP)\
                        .replace("__PORT__", str(PORT))\
                        .replace("__SERVER_URL__", SERVER_URL)
    return content

if __name__ == "__main__":
    print(f"\n=======================================================")
    print(f"RISKY ASSETS BARCODE SCANNER SERVER IS READY!")
    print(f"Local Laptop Access : http://localhost:{PORT}")
    print(f"Mobile Phone Access: http://{LOCAL_IP}:{PORT}")
    print(f"=======================================================\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT)