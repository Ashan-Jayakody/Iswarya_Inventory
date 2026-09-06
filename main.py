import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import socket
import datetime
import io
import csv
import os
import sys
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Form
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS serial_number VARCHAR(255)")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS notes TEXT")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
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
# 3. Pydantic Models & API Routes
# ---------------------------------------------------------
class AssetModel(BaseModel):
    asset_id: str = Field(..., description="Barcode or QR Code ID")
    name: str
    category: str
    department: str
    location: str
    status: str
    serial_number: Optional[str] = ""
    notes: Optional[str] = ""

class AssetUpdateModel(BaseModel):
    name: str
    category: str
    department: str
    location: str
    status: str
    serial_number: Optional[str] = ""
    notes: Optional[str] = ""

@app.get("/api/network-info")
def get_network_info():
    return {"local_ip": LOCAL_IP, "port": PORT, "server_url": SERVER_URL}

@app.get("/api/assets")
def list_assets(search: Optional[str] = Query(None), department: Optional[str] = Query(None), status: Optional[str] = Query(None)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    query = "SELECT * FROM assets WHERE 1=1"
    params = []
    if search:
        query += " AND (asset_id ILIKE %s OR name ILIKE %s OR location ILIKE %s OR serial_number ILIKE %s)"
        term = f"%{search}%"
        params.extend([term, term, term, term])
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
def create_asset(asset: AssetModel):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT asset_id FROM assets WHERE asset_id = %s", (asset.asset_id.strip(),))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Barcode ID already registered")
    now = datetime.datetime.now()
    cursor.execute("""
        INSERT INTO assets (asset_id, name, category, department, location, status, serial_number, notes, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        asset.asset_id.strip(), asset.name.strip(), asset.category.strip(),
        asset.department.strip(), asset.location.strip(), asset.status.strip(),
        asset.serial_number.strip() if asset.serial_number else "",
        asset.notes.strip() if asset.notes else "", now, now
    ))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Asset registered successfully", "asset_id": asset.asset_id}

@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: str, asset: AssetUpdateModel):
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
        SET name = %s, category = %s, department = %s, location = %s, status = %s, serial_number = %s, notes = %s, updated_at = %s
        WHERE asset_id = %s
    """, (
        asset.name.strip(), asset.category.strip(), asset.department.strip(),
        asset.location.strip(), asset.status.strip(),
        asset.serial_number.strip() if asset.serial_number else "",
        asset.notes.strip() if asset.notes else "", now, asset_id.strip()
    ))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Asset updated successfully", "asset_id": asset_id}

@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: str):
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
    cursor.execute("SELECT asset_id, name, category, department, location, status, serial_number, notes, created_at, updated_at FROM assets ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["Barcode ID", "Name", "Category", "Department", "Location", "Status", "Serial Number", "Notes", "Created At", "Updated At"])
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
    <title>Hospital Asset Scanner</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

    <!-- HTML5 Barcode & QR Code Scanner Library -->
    <script src="https://unpkg.com/html5-qrcode"></script>

    <style>
        :root {
            --bg-color: #0f1216;
            --card-bg: #171b21;
            --card-border: #262c36;
            --input-bg: #0f1216;
            --accent: #388bfd;
            --accent-hover: #2b7ae7;
            --text-main: #f0f4f8;
            --text-muted: #8b94a0;
            --text-subtle: #59616e;
            --radius-md: 10px;
            --radius-lg: 14px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; -webkit-tap-highlight-color: transparent; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; padding-bottom: 84px; }

        header { background: rgba(23, 27, 33, 0.96); backdrop-filter: blur(10px); border-bottom: 1px solid var(--card-border); padding: 12px 20px; position: sticky; top: 0; z-index: 100; display: flex; justify-content: space-between; align-items: center; }
        .brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 0.88rem; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-main); }
        .brand-icon { color: var(--accent); font-size: 1.1rem; }
        .ip-badge { background: #1f2530; color: var(--text-muted); border: 1px solid var(--card-border); padding: 5px 12px; border-radius: 20px; font-size: 0.78rem; font-weight: 500; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: border-color 0.2s ease; }
        .ip-badge strong { color: var(--text-main); }
        .ip-badge:hover { border-color: var(--accent); }

        .container { width: 100%; max-width: 860px; margin: 0 auto; padding: 16px; flex: 1; }

        .tab-nav { display: flex; gap: 6px; margin-bottom: 18px; background: #13171d; padding: 4px; border-radius: var(--radius-md); border: 1px solid var(--card-border); }
        .tab-btn { flex: 1; padding: 10px 14px; border: none; background: transparent; color: var(--text-muted); font-weight: 500; font-size: 0.88rem; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; transition: all 0.2s ease; }
        .tab-btn.active { background: var(--card-bg) !important; color: var(--text-main) !important; border: 1px solid var(--card-border); font-weight: 600; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }

        .tab-content { display: none !important; }
        .tab-content.active { display: block !important; animation: fadeIn 0.2s ease; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }

        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius-lg); padding: 18px; margin-bottom: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25); }
        .card-title { font-size: 0.95rem; font-weight: 600; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; color: var(--text-main); letter-spacing: 0.01em; }

        #reader-wrapper { position: relative; border-radius: var(--radius-md); overflow: hidden; border: 1px solid var(--card-border); background: #000; min-height: 240px; }
        #reader { width: 100%; border: none !important; }
        #reader img { display: none !important; }
        #reader video { width: 100% !important; object-fit: cover; }
        #reader__dashboard_section_csr button { padding: 8px 14px; border-radius: 6px; background: var(--card-bg); color: var(--text-main); border: 1px solid var(--card-border); font-size: 0.85rem; font-weight: 500; cursor: pointer; margin: 4px; }
        #reader__camera_selection { padding: 8px 12px; border-radius: 6px; background: var(--input-bg); color: var(--text-main); border: 1px solid var(--card-border); width: 100%; outline: none; margin-bottom: 8px; font-size: 0.88rem; }

        .scanner-actions { display: flex; gap: 10px; margin-top: 14px; }
        .btn { min-height: 44px; padding: 10px 16px; border-radius: var(--radius-md); border: 1px solid transparent; font-weight: 500; font-size: 0.88rem; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.15s ease; text-decoration: none; }
        .btn-primary { background: var(--accent); color: #ffffff; border-color: var(--accent); }
        .btn-primary:active { background: var(--accent-hover); }
        .btn-secondary { background: #1f2530; color: var(--text-main); border-color: var(--card-border); }
        .btn-secondary:active { background: #28303e; }
        .btn-outline { background: transparent; color: var(--text-muted); border-color: var(--card-border); }
        .btn-danger { background: rgba(224, 86, 86, 0.12); color: #f87171; border-color: rgba(224, 86, 86, 0.25); }

        .file-upload-btn { position: relative; overflow: hidden; width: 100%; }
        .file-upload-btn input[type=file] { position: absolute; left: 0; top: 0; opacity: 0; width: 100%; height: 100%; cursor: pointer; }

        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 0.78rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }
        .form-control { width: 100%; min-height: 44px; padding: 10px 14px; background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 8px; color: var(--text-main); font-size: 0.92rem; outline: none; transition: border-color 0.2s ease; }
        .form-control:focus { border-color: var(--accent); }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        @media (max-width: 600px) { .form-row { grid-template-columns: 1fr; } }

        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 500; background: #1f2530; border: 1px solid var(--card-border); color: var(--text-main); }
        .badge-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
        .badge-dot.active { background: #34d399; }
        .badge-dot.maintenance { background: #fbbf24; }
        .badge-dot.order { background: #f87171; }

        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }
        th { background: #111419; padding: 10px 14px; color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--card-border); }
        td { padding: 12px 14px; border-bottom: 1px solid var(--card-border); }
        tr:hover td { background: rgba(255, 255, 255, 0.015); }

        .qr-center { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; text-align: center; }

        #toast { position: fixed; bottom: 84px; left: 50%; transform: translateX(-50%); background: #1f2530; border: 1px solid var(--card-border); color: var(--text-main); padding: 10px 20px; border-radius: 24px; font-size: 0.85rem; font-weight: 500; box-shadow: 0 8px 24px rgba(0,0,0,0.4); display: none; z-index: 1000; transition: all 0.2s ease; }

        .mobile-nav { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(23, 27, 33, 0.96); backdrop-filter: blur(10px); border-top: 1px solid var(--card-border); display: flex; justify-content: space-around; padding: 8px 0; z-index: 200; }
        .mobile-nav-btn { display: flex; flex-direction: column; align-items: center; gap: 3px; background: none; border: none; color: var(--text-muted); font-size: 0.72rem; font-weight: 500; cursor: pointer; padding: 6px 16px; border-radius: 8px; transition: color 0.15s ease; }
        .mobile-nav-btn.active { color: var(--accent); font-weight: 600; }
        .mobile-nav-icon { font-size: 1.1rem; }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <span class="brand-icon">✚</span>
            <span>Hospital Assets</span>
        </div>
        <div class="ip-badge" onclick="switchTab('pair')">
            <span>Mobile Link:</span>
            <strong>__LOCAL_IP__:__PORT__</strong>
        </div>
    </header>

    <div class="container">
        <div class="tab-nav">
            <button class="tab-btn active" id="tab-btn-scan" onclick="switchTab('scan')">║▌ Scanner</button>
            <button class="tab-btn" id="tab-btn-inventory" onclick="switchTab('inventory')">📋 Inventory</button>
            <button class="tab-btn" id="tab-btn-pair" onclick="switchTab('pair')">📱 Connect</button>
        </div>

        <!-- TAB 1: SCANNER -->
        <div id="tab-scan" class="tab-content active">
            <div class="card">
                <div class="card-title">
                    <span>Barcode & QR Camera</span>
                    <span class="badge"><span class="badge-dot active"></span>Camera Ready</span>
                </div>

                <div id="reader-wrapper">
                    <div id="reader"></div>
                </div>

                <div class="scanner-actions">
                    <div class="btn btn-secondary file-upload-btn">
                        <span>📸 Take Photo / Upload Barcode Image</span>
                        <input type="file" id="qr-input-file" accept="image/*" capture="environment">
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">⌨️ Manual / Scanner Input</div>
                <form onsubmit="event.preventDefault(); lookupManualId();" style="display: flex; gap: 8px;">
                    <input type="text" id="manual-asset-id" class="form-control" placeholder="Scan or type Barcode ID..." onkeydown="if(event.key==='Enter'){event.preventDefault(); lookupManualId();}">
                    <button type="submit" class="btn btn-secondary" style="min-width: 90px;">Lookup</button>
                </form>
            </div>

            <div id="scan-result-card"></div>
        </div>

        <!-- TAB 2: INVENTORY -->
        <div id="tab-inventory" class="tab-content">
            <div class="card">
                <div class="card-title">
                    <span>Hospital Inventory</span>
                    <a href="/export" class="btn btn-secondary" style="font-size: 0.8rem; min-height: 36px; padding: 4px 12px;">📥 Export CSV</a>
                </div>

                <div class="form-row" style="margin-bottom: 16px;">
                    <input type="text" id="inv-search" class="form-control" placeholder="Search by name, ID, or room..." oninput="loadInventory()">
                    <select id="inv-dept-filter" class="form-control" onchange="loadInventory()">
                        <option value="">All Departments</option>
                        <option value="Emergency">Emergency / ER</option>
                        <option value="ICU">ICU / Critical Care</option>
                        <option value="Radiology">Radiology / Imaging</option>
                        <option value="Surgery">Surgery / OR</option>
                        <option value="Pediatrics">Pediatrics</option>
                        <option value="Cardiology">Cardiology</option>
                        <option value="General Ward">General Ward</option>
                        <option value="IT Hardware">IT & Telecom</option>
                        <option value="Facilities">Facilities & Maintenance</option>
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
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="inventory-table-body">
                            <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Loading inventory...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: MOBILE PAIR -->
        <div id="tab-pair" class="tab-content">
            <div class="card qr-center">
                <h3 style="font-size: 1.1rem; font-weight: 600; margin-bottom: 6px;">📱 Mobile Browser Link</h3>
                <p style="color: var(--text-muted); font-size: 0.88rem; max-width: 480px; line-height: 1.5;">
                    Ensure your mobile phone is connected to the <strong>same Wi-Fi network</strong> as this host laptop, then open this address in Chrome or Safari:
                </p>

                <div style="background: #111419; border: 1px solid var(--card-border); padding: 14px 20px; border-radius: var(--radius-md); text-align: center; margin: 20px 0; width: 100%; max-width: 440px;">
                    <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em;">Mobile Web Address:</div>
                    <strong id="mobile-url-display" style="font-size: 1.35rem; color: var(--accent);">__SERVER_URL__</strong>
                </div>

                <div style="text-align: left; background: var(--input-bg); border: 1px solid var(--card-border); padding: 16px; border-radius: var(--radius-md); font-size: 0.85rem; width: 100%; max-width: 500px; color: var(--text-muted);">
                    <strong style="color: var(--text-main); font-size: 0.9rem;">💡 Scanning Quick Tips:</strong>
                    <ul style="margin-left: 18px; margin-top: 6px; line-height: 1.6;">
                        <li><strong>For 1-Tap Photo Scan:</strong> Tap <strong>📸 Take Photo / Upload Barcode Image</strong> to snap any physical barcode tag.</li>
                        <li><strong>Audio & Haptic Feedback:</strong> Plays a clean beep and vibrates your phone upon a successful decode.</li>
                        <li><strong>1D Barcodes Supported:</strong> CODE128, CODE39, CODE93, EAN-13, EAN-8, UPC-A, UPC-E, Codabar, and QR Codes.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <div class="mobile-nav">
        <button class="mobile-nav-btn active" id="mob-btn-scan" onclick="switchTab('scan')">
            <span class="mobile-nav-icon">║▌</span>
            <span>Scanner</span>
        </button>
        <button class="mobile-nav-btn" id="mob-btn-inventory" onclick="switchTab('inventory')">
            <span class="mobile-nav-icon">📋</span>
            <span>Inventory</span>
        </button>
        <button class="mobile-nav-btn" id="mob-btn-pair" onclick="switchTab('pair')">
            <span class="mobile-nav-icon">📱</span>
            <span>Connect</span>
        </button>
    </div>

    <div id="toast">Notification</div>

    <script>
        const SERVER_URL = window.location.origin;
        let html5QrcodeScanner = null;

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
            if(status === 'In Maintenance') dotClass = "maintenance";
            if(status === 'Out of Order') dotClass = "order";
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
                    <div style="font-size: 0.95rem; color: var(--text-muted);">Searching Barcode: <strong style="color: var(--text-main);">${assetId}</strong>...</div>
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
                            <span style="font-size: 1.15rem; font-weight: 600; color: var(--text-main);">📦 ${asset.name}</span>
                            <div style="font-size: 0.82rem; color: var(--accent); font-weight: 500; margin-top: 2px;">ID: ${asset.asset_id}</div>
                        </div>
                        ${getStatusBadgeHtml(asset.status)}
                    </div>

                    <div style="background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin-bottom: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.9rem;">
                        <div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">CATEGORY</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.category || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">DEPARTMENT</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.department || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">LOCATION</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">📍 ${asset.location || 'Unspecified'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">STATUS</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.status}</div>
                        </div>
                        ${asset.serial_number ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">SERIAL / MODEL</div>
                            <div style="font-weight: 500; color: var(--text-main); margin-top: 2px;">${asset.serial_number}</div>
                        </div>` : ''}
                        ${asset.notes ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">NOTES</div>
                            <div style="font-weight: 400; color: var(--text-muted); margin-top: 2px;">${asset.notes}</div>
                        </div>` : ''}
                        <div style="grid-column: span 2; border-top: 1px solid var(--card-border); padding-top: 8px; font-size: 0.75rem; color: var(--text-subtle);">
                            🕒 Last Updated: ${formattedDate}
                        </div>
                    </div>

                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-secondary" style="flex: 1;" onclick="toggleEditForm()">✏️ Edit Details</button>
                        <button class="btn btn-primary" onclick="document.getElementById('scan-result-card').innerHTML=''">Scan Another</button>
                    </div>

                    <form id="edit-asset-form" style="display: none; margin-top: 16px; border-top: 1px solid var(--card-border); padding-top: 16px;" onsubmit="submitAssetUpdate(event, '${asset.asset_id}')">
                        <h4 style="margin-bottom: 12px; font-size: 0.95rem; font-weight: 600; color: var(--text-main);">✏️ Edit Asset Details</h4>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label>Asset Name</label>
                                <input type="text" id="edit-name" class="form-control" value="${asset.name}" required>
                            </div>
                            <div class="form-group">
                                <label>Status</label>
                                <select id="edit-status" class="form-control">
                                    <option value="Active" ${asset.status === 'Active' ? 'selected' : ''}>Active / Available</option>
                                    <option value="In Maintenance" ${asset.status === 'In Maintenance' ? 'selected' : ''}>In Maintenance</option>
                                    <option value="Out of Order" ${asset.status === 'Out of Order' ? 'selected' : ''}>Out of Order</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Department</label>
                                <select id="edit-dept" class="form-control">
                                    <option value="Emergency" ${asset.department === 'Emergency' ? 'selected' : ''}>Emergency / ER</option>
                                    <option value="ICU" ${asset.department === 'ICU' ? 'selected' : ''}>ICU / Critical Care</option>
                                    <option value="Radiology" ${asset.department === 'Radiology' ? 'selected' : ''}>Radiology / Imaging</option>
                                    <option value="Surgery" ${asset.department === 'Surgery' ? 'selected' : ''}>Surgery / OR</option>
                                    <option value="Pediatrics" ${asset.department === 'Pediatrics' ? 'selected' : ''}>Pediatrics</option>
                                    <option value="Cardiology" ${asset.department === 'Cardiology' ? 'selected' : ''}>Cardiology</option>
                                    <option value="General Ward" ${asset.department === 'General Ward' ? 'selected' : ''}>General Ward</option>
                                    <option value="IT Hardware" ${asset.department === 'IT Hardware' ? 'selected' : ''}>IT Hardware</option>
                                    <option value="Facilities" ${asset.department === 'Facilities' ? 'selected' : ''}>Facilities</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Location / Room</label>
                                <input type="text" id="edit-location" class="form-control" value="${asset.location}" required>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Serial Number</label>
                                <input type="text" id="edit-serial" class="form-control" value="${asset.serial_number || ''}">
                            </div>
                            <div class="form-group">
                                <label>Notes</label>
                                <input type="text" id="edit-notes" class="form-control" value="${asset.notes || ''}">
                            </div>
                        </div>

                        <input type="hidden" id="edit-category" value="${asset.category}">

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
            resCard.innerHTML = `
                <div class="card">
                    <div class="card-title">
                        <span>🆕 Register New Asset</span>
                        <span class="badge"><span class="badge-dot maintenance"></span>New Barcode</span>
                    </div>

                    <form id="new-asset-form" onsubmit="submitNewAsset(event)">
                        <div class="form-group">
                            <label>Scanned Barcode ID</label>
                            <input type="text" id="new-id" class="form-control" value="${assetId}" readonly style="background: rgba(255,255,255,0.03); font-weight: 600; color: var(--accent);">
                        </div>

                        <div class="form-group">
                            <label>Asset Name</label>
                            <input type="text" id="new-name" class="form-control" placeholder="e.g. Patient Monitor X200" required>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label>Category</label>
                                <select id="new-category" class="form-control">
                                    <option value="Medical Equipment">Medical Equipment</option>
                                    <option value="Diagnostic Equipment">Diagnostic Equipment</option>
                                    <option value="Patient Care">Patient Care</option>
                                    <option value="IT Hardware">IT Hardware</option>
                                    <option value="Furniture">Furniture</option>
                                    <option value="Laboratory">Laboratory</option>
                                    <option value="Facilities">Facilities</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Department</label>
                                <select id="new-department" class="form-control">
                                    <option value="Emergency">Emergency / ER</option>
                                    <option value="ICU">ICU / Critical Care</option>
                                    <option value="Radiology">Radiology / Imaging</option>
                                    <option value="Surgery">Surgery / OR</option>
                                    <option value="Pediatrics">Pediatrics</option>
                                    <option value="Cardiology">Cardiology</option>
                                    <option value="General Ward">General Ward</option>
                                    <option value="IT Hardware">IT & Telecom</option>
                                    <option value="Facilities">Facilities</option>
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
                                    <option value="Active">Active / In Use</option>
                                    <option value="In Maintenance">In Maintenance</option>
                                    <option value="Out of Order">Out of Order</option>
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if(res.ok) {
                showToast("Asset Saved Successfully!");
                handleScannedId(payload.asset_id);
            } else {
                const data = await res.json();
                alert("Error saving asset: " + (data.detail || "Failed"));
            }
        }

        async function submitAssetUpdate(e, assetId) {
            e.preventDefault();
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if(res.ok) {
                showToast("Asset Updated!");
                handleScannedId(assetId);
            } else {
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
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No assets registered yet. Scan a barcode to add one.</td></tr>';
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
                            <td>
                                <button class="btn btn-secondary" style="padding: 4px 10px; min-height: 32px; font-size: 0.78rem;" onclick="switchTab('scan'); handleScannedId('${a.asset_id}');">Edit</button>
                                <button class="btn btn-danger" style="padding: 4px 10px; min-height: 32px; font-size: 0.78rem;" onclick="deleteAsset('${a.asset_id}')">Delete</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch(err) {
                console.error("Inventory error:", err);
            }
        }

        async function deleteAsset(assetId) {
            if(!confirm("Are you sure you want to delete barcode " + assetId + " from database?")) return;
            const res = await fetch('/api/assets/' + encodeURIComponent(assetId), { method: 'DELETE' });
            if(res.ok) {
                showToast("Asset deleted");
                loadInventory();
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
    print(f"HOSPITAL ASSETS BARCODE SCANNER SERVER IS READY!")
    print(f"Local Laptop Access : http://localhost:{PORT}")
    print(f"Mobile Phone Access: http://{LOCAL_IP}:{PORT}")
    print(f"=======================================================\n")
    uvicorn.run(app, host="0.0.0.0", port=PORT)