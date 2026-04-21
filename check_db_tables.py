import mysql.connector
from fraud_detection.config import DB_CONFIG

try:
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Get existing tables
    cur.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s", (DB_CONFIG['database'],))
    existing_tables = [row[0] for row in cur.fetchall()]
    
    print("✓ Connected to database:", DB_CONFIG['database'])
    print(f"\nExisting tables ({len(existing_tables)}):")
    for table in sorted(existing_tables):
        print(f"  - {table}")
    
    cur.close()
    conn.close()
except Exception as e:
    print(f"❌ Error: {e}")
