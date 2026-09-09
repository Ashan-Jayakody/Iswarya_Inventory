import psycopg2
from dotenv import load_dotenv
import os
import random
import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or os.getenv("POSTGRES_URL_NON_POOLING")

DB_HOST = os.getenv("POSTGRES_HOST") or "localhost"
port_env = os.getenv("POSTGRES_PORT")
try:
    DB_PORT = int(port_env) if port_env and port_env.strip() else 5432
except (ValueError, TypeError):
    DB_PORT = 5432
DB_NAME = os.getenv("POSTGRES_DB") or "hospital_assets"
DB_USER = os.getenv("POSTGRES_USER") or "postgres"
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD") or "postgrespassword"

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

CATEGORIES_ITEMS = {
    "Medical & Surgical Equipment": [
        "Patient Monitor X200", "Infusion Pump IP-40", "Surgical Lamp SL-5", 
        "Defibrillator DF-300", "Anesthesia Machine AM-90", "Ultrasound Scanner US-10", 
        "Ventilator VT-500", "Electrocardiograph ECG-12", "Pulse Oximeter PO-20", 
        "Syringe Pump SP-15", "Nebulizer NB-80", "Blood Pressure Monitor BP-5"
    ],
    "Office equipment": [
        "Paper Shredder PS-80", "Laminator LM-200", "Ergonomic Desk Chair", 
        "Whiteboard 120x90", "Barcode Scanner BS-50", "Label Printer LP-30",
        "Document Scanner DS-100", "Projector HD-4K", "Paper Trimmer PT-15"
    ],
    "IT equipment": [
        "Dell OptiPlex 7090", "HP ProDesk 400", "Lenovo ThinkPad L14", 
        "Cisco Catalyst Switch 24P", "Epson EcoTank Printer", "APC Smart-UPS 1500VA", 
        "Samsung 27 inch Monitor", "Logitech HD Webcam", "TP-Link Wi-Fi AP 6"
    ],
    "Furniture & fixtures": [
        "Hospital Bed Electric HB-4", "Overbed Table OT-12", "IV Pole Stand IP-3", 
        "Bedside Cabinet BC-9", "Examination Table ET-2", "Doctor Desk Wood D-1",
        "Visitor Chair Chrome", "Medicine Cabinet Lockable", "Screen Partition 3-Fold"
    ],
    "Intangible assets": [
        "EMR Software License 2026", "PACS Storage License", "Hospital Information System Seat", 
        "Antivirus Enterprise Sub", "Billing Module Core License", "Lab Management System Addon"
    ],
    "Other equipment": [
        "Autoclave Sterilizer AS-50", "Wheelchair Standard W-10", "Stretcher Trolley ST-8", 
        "Oxygen Cylinder 40L", "Suction Machine SM-15", "Centrifuge Machine CM-20",
        "Microscope Binocular MB-4", "Reagent Refrigerator RR-15"
    ]
}

DEPARTMENTS = [
    "Admin", "Finance", "Lab", "Nursing", "Hr", 
    "It", "Reception/billing", "Councelling", "Clinical"
]

STATUSES = ["Active", "Active", "Active", "Damaged", "Disposable", "Repair required"]

LOCATIONS = [
    "Room 101, Bed A", "Room 102, Bed B", "Room 204", "Room 305", "ICU Ward 2",
    "Lab Counter 1", "Lab Counter 3", "Server Room Rack 02", "Reception Desk 1",
    "Billing Counter 3", "Finance Office Desk 4", "Clinical Room 12", "Counseling Room B"
]

def seed_assets(count=1200):
    print("Connecting to database...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return

    # Ensure assets table exists
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
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM assets")
    existing_count = cursor.fetchone()[0]
    print(f"Current asset count in database: {existing_count}")

    print(f"Generating {count} realistic asset records...")

    categories_keys = list(CATEGORIES_ITEMS.keys())
    batch_data = []

    now = datetime.datetime.now()

    for i in range(1, count + 1):
        asset_id = f"BC-{10000 + i}"
        category = random.choice(categories_keys)
        item_base_name = random.choice(CATEGORIES_ITEMS[category])
        name = f"{item_base_name} #{i}"
        department = random.choice(DEPARTMENTS)
        location = random.choice(LOCATIONS)
        status = random.choice(STATUSES)
        serial_number = f"SN-{random.randint(1000000, 9999999)}"
        notes = f"Batch seed item #{i} for performance testing"
        created_by = "SeedScript"
        updated_by = "SeedScript"
        
        days_ago = random.randint(0, 60)
        timestamp = now - datetime.timedelta(days=days_ago, minutes=random.randint(0, 1440))

        batch_data.append((
            asset_id, name, category, department, location, status,
            serial_number, notes, created_by, updated_by, timestamp, timestamp
        ))

    print("Inserting batch data into database...")
    query = """
        INSERT INTO assets (asset_id, name, category, department, location, status, serial_number, notes, created_by, updated_by, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_id) DO UPDATE SET
            name = EXCLUDED.name,
            category = EXCLUDED.category,
            department = EXCLUDED.department,
            location = EXCLUDED.location,
            status = EXCLUDED.status,
            serial_number = EXCLUDED.serial_number,
            notes = EXCLUDED.notes,
            updated_by = EXCLUDED.updated_by,
            updated_at = EXCLUDED.updated_at
    """

    cursor.executemany(query, batch_data)
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM assets")
    new_total = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    print(f"\n=======================================================")
    print(f"SUCCESS! Seeded {count} assets into database.")
    print(f"Total asset records in Neon database: {new_total}")
    print(f"=======================================================\n")

if __name__ == "__main__":
    seed_assets(1200)
