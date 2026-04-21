"""
Migration script to add Phase 1 new tables
Adds 4 new tables for: merchant recurrence, feedback, baselines, velocity patterns
"""

import mysql.connector
from fraud_detection.config import DB_CONFIG

def add_new_tables():
    """Add new Phase 1 tables to existing database"""
    
    new_tables = {
        'merchant_recurrence': """
CREATE TABLE IF NOT EXISTS merchant_recurrence (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    merchant_id         VARCHAR(100) NOT NULL,
    merchant_name       VARCHAR(255),
    flagged_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    transaction_id      VARCHAR(32),
    risk_band           VARCHAR(20),
    reason              TEXT,
    INDEX idx_merchant_window (merchant_id, flagged_at),
    INDEX idx_created (flagged_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",
        
        'feedback_log': """
CREATE TABLE IF NOT EXISTS feedback_log (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id      VARCHAR(32) NOT NULL,
    case_id             VARCHAR(32),
    feedback_type       VARCHAR(50) NOT NULL,
    feedback_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ground_truth        VARCHAR(20),
    system_decision     VARCHAR(20),
    correct_prediction  TINYINT,
    rule_triggered      VARCHAR(100),
    confidence_score    DECIMAL(6,4),
    analyst_notes       TEXT,
    INDEX idx_txn (transaction_id),
    INDEX idx_case (case_id),
    INDEX idx_feedback_type (feedback_type),
    INDEX idx_date (feedback_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",
        
        'transaction_baseline': """
CREATE TABLE IF NOT EXISTS transaction_baseline (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    card_number         VARCHAR(20) NOT NULL UNIQUE,
    email               VARCHAR(120),
    device_id           VARCHAR(64),
    avg_transaction_amt DECIMAL(14,2),
    median_transaction_amt DECIMAL(14,2),
    stddev_amount       DECIMAL(14,2),
    typical_merchants   TEXT,
    typical_categories  TEXT,
    typical_countries   TEXT,
    typical_hours       TEXT,
    typical_devices     INT,
    typical_ips         INT,
    avg_daily_count     DECIMAL(6,2),
    max_daily_count     INT,
    account_age_days    INT,
    txn_count_used      INT,
    last_computed       TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_card (card_number),
    INDEX idx_email (email),
    INDEX idx_device (device_id),
    INDEX idx_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",
        
        'velocity_patterns': """
CREATE TABLE IF NOT EXISTS velocity_patterns (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    card_number         VARCHAR(20),
    device_id           VARCHAR(64),
    merchant_id         VARCHAR(100),
    pattern_type        VARCHAR(30),
    burst_count_5min    INT,
    burst_count_1hr     INT,
    sustained_velocity_24h INT,
    geographic_countries INT,
    anomaly_score       DECIMAL(6,4),
    detected_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_card (card_number),
    INDEX idx_device (device_id),
    INDEX idx_merchant (merchant_id),
    INDEX idx_pattern (pattern_type),
    INDEX idx_detected (detected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""
    }
    
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    try:
        created_count = 0
        already_exist = 0
        
        for table_name, create_sql in new_tables.items():
            # Check if table exists
            cur.execute("SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s", 
                       (DB_CONFIG['database'], table_name))
            
            if cur.fetchone():
                print(f"  ℹ️  {table_name} — already exists (skipped)")
                already_exist += 1
            else:
                cur.execute(create_sql)
                conn.commit()
                print(f"  ✅ {table_name} — created")
                created_count += 1
        
        print(f"\n{'='*60}")
        print(f"Migration Complete:")
        print(f"  ✅ Created: {created_count} new tables")
        print(f"  ℹ️  Already exist: {already_exist} tables")
        print(f"{'='*60}\n")
        
        return created_count > 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        conn.rollback()
        return False
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    print("Phase 1 Migration: Adding new tables")
    print("="*60)
    add_new_tables()
