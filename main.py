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
    <title>Hospital Asset Barcode Scanner</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

    <!-- HTML5 Barcode & QR Code Scanner Library -->
    <script src="https://unpkg.com/html5-qrcode"></script>

    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --accent-blue: #38bdf8;
            --accent-green: #22c55e;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --input-bg: #0f172a;
            --radius-md: 12px;
            --radius-lg: 16px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; }
        body { background-color: var(--bg-color); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; padding-bottom: 80px; }

        header { background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(12px); border-bottom: 1px solid var(--card-border); padding: 12px 20px; position: sticky; top: 0; z-index: 100; display: flex; justify-content: space-between; align-items: center; }
        .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1rem; color: var(--text-main); }
        .brand-icon { background: linear-gradient(135deg, #0284c7, #38bdf8); width: 34px; height: 34px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
        .ip-badge { background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); border: 1px solid rgba(56, 189, 248, 0.3); padding: 6px 12px; border-radius: 20px; font-size: 0.82rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; }

        .container { width: 100%; max-width: 900px; margin: 0 auto; padding: 16px; flex: 1; }

        .tab-nav { display: flex; gap: 8px; margin-bottom: 20px; background: var(--card-bg); padding: 6px; border-radius: var(--radius-md); border: 1px solid var(--card-border); overflow-x: auto; }
        .tab-btn { flex: 1; padding: 12px 14px; border: none; background: transparent; color: var(--text-muted); font-weight: 600; font-size: 0.95rem; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; white-space: nowrap; transition: all 0.2s ease; }
        .tab-btn.active { background: var(--accent-blue) !important; color: #0f172a !important; }

        .tab-content { display: none !important; }
        .tab-content.active { display: block !important; animation: fadeIn 0.25s ease-in-out; }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: var(--radius-lg); padding: 20px; margin-bottom: 16px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }
        .card-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; }

        #reader-wrapper { position: relative; border-radius: var(--radius-md); overflow: hidden; border: 2px dashed var(--accent-blue); background: #000; min-height: 240px; }
        #reader { width: 100%; }

        .scanner-actions { display: flex; gap: 10px; margin-top: 14px; }
        .btn { padding: 12px 18px; border-radius: var(--radius-md); border: none; font-weight: 600; font-size: 0.95rem; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.2s ease; text-decoration: none; }
        .btn-primary { background: var(--accent-blue); color: #0f172a; }
        .btn-secondary { background: #334155; color: var(--text-main); }
        .btn-success { background: var(--accent-green); color: #0f172a; }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }

        .file-upload-btn { position: relative; overflow: hidden; width: 100%; }
        .file-upload-btn input[type=file] { position: absolute; left: 0; top: 0; opacity: 0; width: 100%; height: 100%; cursor: pointer; }

        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 12px 14px; background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 8px; color: var(--text-main); font-size: 0.95rem; outline: none; }
        .form-control:focus { border-color: var(--accent-blue); }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        @media (max-width: 600px) { .form-row { grid-template-columns: 1fr; } }

        .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; }
        .badge-active { background: rgba(34, 197, 94, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .badge-maintenance { background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); border: 1px solid var(--accent-amber); }
        .badge-order { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }

        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th { background: #0f172a; padding: 12px 14px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); }
        td { padding: 12px 14px; border-bottom: 1px solid var(--card-border); }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        .qr-center { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; text-align: center; }
        .barcode-box { background: #ffffff; padding: 16px; border-radius: var(--radius-md); margin: 16px 0; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5); min-width: 260px; display: flex; flex-direction: column; align-items: center; justify-content: center; }

        #toast { position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%); background: var(--accent-green); color: #0f172a; padding: 12px 24px; border-radius: 30px; font-weight: 700; box-shadow: 0 10px 20px rgba(0,0,0,0.4); display: none; z-index: 1000; }

        .mobile-nav { position: fixed; bottom: 0; left: 0; right: 0; background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(12px); border-top: 1px solid var(--card-border); display: flex; justify-content: space-around; padding: 10px 0; z-index: 200; }
        .mobile-nav-btn { display: flex; flex-direction: column; align-items: center; gap: 4px; background: none; border: none; color: var(--text-muted); font-size: 0.75rem; font-weight: 600; cursor: pointer; padding: 4px 12px; border-radius: 8px; }
        .mobile-nav-btn.active { color: var(--accent-blue); background: rgba(56, 189, 248, 0.1); }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="brand-icon">🏥</div>
            <span>Hospital Assets</span>
        </div>
        <div class="ip-badge" onclick="switchTab('pair')">
            <span>📱 Mobile Link:</span>
            <strong>__LOCAL_IP__:__PORT__</strong>
        </div>
    </header>

    <div class="container">
        <div class="tab-nav">
            <button class="tab-btn active" id="tab-btn-scan" onclick="switchTab('scan')">║▌ Barcode Scanner</button>
            <button class="tab-btn" id="tab-btn-inventory" onclick="switchTab('inventory')">📋 Inventory</button>
            <button class="tab-btn" id="tab-btn-pair" onclick="switchTab('pair')">📱 Mobile Pair</button>
        </div>

        <!-- TAB 1: SCANNER -->
        <div id="tab-scan" class="tab-content active">
            <div class="card">
                <div class="card-title">
                    <span>Scan Asset Barcode</span>
                    <span id="scan-mode-badge" class="badge badge-active">1D Barcode & QR</span>
                </div>

                <div id="reader-wrapper">
                    <div id="reader"></div>
                </div>

                <div class="scanner-actions">
                    <div class="btn btn-primary file-upload-btn">
                        <span>📸 Take Photo / Upload Barcode Image</span>
                        <input type="file" id="qr-input-file" accept="image/*" capture="environment">
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">⌨️ Or Type Barcode ID</div>
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="manual-asset-id" class="form-control" placeholder="Enter Barcode ID (e.g. BAR-100492)">
                    <button class="btn btn-secondary" onclick="lookupManualId()">Lookup</button>
                </div>
            </div>

            <div id="scan-result-card"></div>
        </div>

        <!-- TAB 2: INVENTORY -->
        <div id="tab-inventory" class="tab-content">
            <div class="card">
                <div class="card-title">
                    <span>Hospital Asset Inventory</span>
                    <a href="/export" class="btn btn-secondary" style="font-size: 0.85rem; padding: 6px 12px;">📥 Export CSV</a>
                </div>

                <div class="form-row" style="margin-bottom: 16px;">
                    <input type="text" id="inv-search" class="form-control" placeholder="Search by name, Barcode ID, or room..." oninput="loadInventory()">
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
                            <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading inventory...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: MOBILE PAIR -->
        <div id="tab-pair" class="tab-content">
            <div class="card qr-center">
                <h3>📱 Connect Your Mobile Phone</h3>
                <p style="color: var(--text-muted); margin-top: 6px; max-width: 480px;">
                    Ensure your phone is connected to the <strong>same Wi-Fi network</strong> as this laptop, then open this address in your mobile web browser:
                </p>

                <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid var(--accent-blue); padding: 16px 24px; border-radius: var(--radius-md); text-align: center; margin: 20px 0; width: 100%; max-width: 480px;">
                    <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">Mobile Browser Web Address:</div>
                    <strong style="font-size: 1.5rem; color: var(--accent-blue);">__SERVER_URL__</strong>
                </div>

                <div style="text-align: left; background: var(--input-bg); border: 1px solid var(--card-border); padding: 16px; border-radius: var(--radius-md); font-size: 0.88rem; width: 100%; max-width: 550px;">
                    <strong style="color: var(--accent-green); font-size: 0.95rem;">💡 Barcode Scanning Tip:</strong>
                    <ul style="margin-left: 20px; margin-top: 6px; color: var(--text-muted); line-height: 1.6;">
                        <li><strong>For 1-Tap Photo Scan:</strong> Tap <strong>📸 Take Photo / Upload Barcode Image</strong> on the Scanner tab to snap any barcode label directly.</li>
                        <li><strong>1D Barcodes Supported:</strong> CODE128, CODE39, EAN-13, UPC-A, Codabar, and QR Codes!</li>
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
            <span>Pair</span>
        </button>
    </div>

    <div id="toast">Notification</div>

    <script>
        const SERVER_URL = "__SERVER_URL__";
        let html5QrcodeScanner = null;

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
            try { startBarcodeScanner(); } catch(e) {}
            try { loadInventory(); } catch(e) {}
        });

        // Configured for 1D Barcodes & QR Codes
        function startBarcodeScanner() {
            if (typeof Html5QrcodeScanner === 'undefined') return;
            if (html5QrcodeScanner) {
                try { html5QrcodeScanner.clear(); } catch(e) {}
            }

            try {
                html5QrcodeScanner = new Html5QrcodeScanner(
                    "reader",
                    { 
                        fps: 15, 
                        qrbox: { width: 280, height: 160 }, // Wide box optimized for 1D barcodes
                        formatsToSupport: [
                            Html5QrcodeSupportedFormats.CODE_128,
                            Html5QrcodeSupportedFormats.CODE_39,
                            Html5QrcodeSupportedFormats.EAN_13,
                            Html5QrcodeSupportedFormats.UPC_A,
                            Html5QrcodeSupportedFormats.EAN_8,
                            Html5QrcodeSupportedFormats.QR_CODE
                        ],
                        experimentalFeatures: { useBarCodeDetectorIfSupported: true }
                    },
                    false
                );
                html5QrcodeScanner.render(onScanSuccess, onScanError);
            } catch(err) {
                console.error("Barcode camera error:", err);
            }
        }

        function onScanSuccess(decodedText) {
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
                <div class="card" style="text-align: center; padding: 30px;">
                    <div style="font-size: 1.2rem;">🔍 Searching Database for Barcode: <strong>${assetId}</strong>...</div>
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
                alert("Network error communicating with laptop database.");
            }
        }

        function renderExistingAssetCard(asset) {
            const resCard = document.getElementById('scan-result-card');
            let badgeClass = "badge-active";
            if(asset.status === 'In Maintenance') badgeClass = "badge-maintenance";
            if(asset.status === 'Out of Order') badgeClass = "badge-order";

            const formattedDate = asset.updated_at ? new Date(asset.updated_at).toLocaleString() : 'Just now';

            resCard.innerHTML = `
                <div class="card" style="border: 2px solid var(--accent-blue);">
                    <div class="card-title" style="border-bottom: 1px solid var(--card-border); padding-bottom: 10px; margin-bottom: 14px;">
                        <div>
                            <span style="font-size: 1.3rem; font-weight: 700; color: var(--text-main);">📦 ${asset.name}</span>
                            <div style="font-size: 0.85rem; color: var(--accent-blue); font-weight: 600; margin-top: 2px;">Barcode ID: ${asset.asset_id}</div>
                        </div>
                        <span class="badge ${badgeClass}" style="font-size: 0.85rem; padding: 6px 12px;">${asset.status}</span>
                    </div>

                    <div style="background: var(--input-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 16px; margin-bottom: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.95rem;">
                        <div>
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">CATEGORY</div>
                            <div style="font-weight: 700; color: var(--text-main); font-size: 1.05rem;">${asset.category || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">DEPARTMENT</div>
                            <div style="font-weight: 700; color: var(--text-main); font-size: 1.05rem;">${asset.department || 'General'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">LOCATION / ROOM</div>
                            <div style="font-weight: 700; color: var(--accent-green); font-size: 1.05rem;">📍 ${asset.location || 'Unspecified'}</div>
                        </div>
                        <div>
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">CURRENT STATUS</div>
                            <div style="font-weight: 700; color: var(--text-main);">${asset.status}</div>
                        </div>
                        ${asset.serial_number ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">SERIAL / MODEL</div>
                            <div style="font-weight: 600; color: var(--text-main);">${asset.serial_number}</div>
                        </div>` : ''}
                        ${asset.notes ? `
                        <div style="grid-column: span 2;">
                            <div style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">NOTES</div>
                            <div style="font-weight: 500; color: var(--text-muted);">${asset.notes}</div>
                        </div>` : ''}
                        <div style="grid-column: span 2; border-top: 1px solid var(--card-border); pt: 8px; font-size: 0.78rem; color: var(--text-muted);">
                            🕒 Last Updated: ${formattedDate}
                        </div>
                    </div>

                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-secondary" style="flex: 1;" onclick="toggleEditForm()">✏️ Edit Details / Update Location</button>
                        <button class="btn btn-primary" onclick="document.getElementById('scan-result-card').innerHTML=''">Scan Another</button>
                    </div>

                    <form id="edit-asset-form" style="display: none; margin-top: 16px; border-top: 1px dashed var(--card-border); padding-top: 16px;" onsubmit="submitAssetUpdate(event, '${asset.asset_id}')">
                        <h4 style="margin-bottom: 12px; color: var(--accent-blue);">✏️ Edit Asset Details</h4>
                        
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
                                <label>Serial Number (Optional)</label>
                                <input type="text" id="edit-serial" class="form-control" value="${asset.serial_number || ''}">
                            </div>
                            <div class="form-group">
                                <label>Notes / Comments</label>
                                <input type="text" id="edit-notes" class="form-control" value="${asset.notes || ''}">
                            </div>
                        </div>

                        <input type="hidden" id="edit-category" value="${asset.category}">

                        <div style="display: flex; gap: 10px; margin-top: 12px;">
                            <button type="submit" class="btn btn-success" style="flex: 1;">💾 Save Changes</button>
                            <button type="button" class="btn btn-secondary" onclick="toggleEditForm()">Cancel</button>
                        </div>
                    </form>
                </div>`;
            
            resCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function toggleEditForm() {
            const form = document.getElementById('edit-asset-form');
            if(form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
        }

        function renderNewAssetForm(assetId) {
            const resCard = document.getElementById('scan-result-card');
            resCard.innerHTML = `
                <div class="card" style="border-left: 5px solid var(--accent-amber);">
                    <div class="card-title" style="color: var(--accent-amber);">
                        <span>🆕 Register New Barcode Asset</span>
                        <span class="badge badge-maintenance">Unregistered</span>
                    </div>

                    <form id="new-asset-form" onsubmit="submitNewAsset(event)">
                        <div class="form-group">
                            <label>Scanned Barcode ID (Locked)</label>
                            <input type="text" id="new-id" class="form-control" value="${assetId}" readonly style="background: rgba(255,255,255,0.05); font-weight: 700; color: var(--accent-blue);">
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
                            <button type="submit" class="btn btn-primary" style="flex: 1;">➕ Save Asset to Laptop Database</button>
                            <button type="button" class="btn btn-secondary" onclick="document.getElementById('scan-result-card').innerHTML=''">Cancel</button>
                        </div>
                    </form>
                </div>`;

            resCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
                showToast("✅ Barcode Asset Saved!");
                handleScannedId(payload.asset_id);
            } else {
                const data = await res.json();
                alert("Error saving: " + (data.detail || "Failed"));
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
                showToast("✅ Asset Details Updated!");
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
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">No assets registered yet. Scan a barcode to add one!</td></tr>';
                    return;
                }

                tbody.innerHTML = assets.map(a => {
                    let badgeClass = "badge-active";
                    if(a.status === 'In Maintenance') badgeClass = "badge-maintenance";
                    if(a.status === 'Out of Order') badgeClass = "badge-order";

                    return `
                        <tr>
                            <td><strong style="color: var(--accent-blue);">${a.asset_id}</strong></td>
                            <td><strong>${a.name}</strong></td>
                            <td>${a.category}</td>
                            <td>${a.department}</td>
                            <td>${a.location}</td>
                            <td><span class="badge ${badgeClass}">${a.status}</span></td>
                            <td>
                                <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.78rem;" onclick="switchTab('scan'); handleScannedId('${a.asset_id}');">Edit</button>
                                <button class="btn btn-danger" style="padding: 4px 8px; font-size: 0.78rem;" onclick="deleteAsset('${a.asset_id}')">Delete</button>
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