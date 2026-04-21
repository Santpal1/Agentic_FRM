"""
db_setup.py — Run once to create MySQL schema and load the dataset.
Usage:
    python db_setup.py              # load all 20k rows
    python db_setup.py --chunk 1    # load rows 0-5000
    python db_setup.py --chunk 2    # load rows 5000-10000
    python db_setup.py --chunk 3    # load rows 10000-15000
    python db_setup.py --chunk 4    # load rows 15000-20000

Requirements:
    pip install mysql-connector-python pandas

Edit DB_CONFIG below. Also add to XAMPP my.ini under [mysqld] then restart MySQL:
    max_allowed_packet=64M
    innodb_buffer_pool_size=512M
    net_read_timeout=300
    net_write_timeout=300
"""

import sys
import mysql.connector
import pandas as pd

# ── Edit these ──────────────────────────────────────
DB_CONFIG = {
    'host':               'localhost',
    'port':               3306,
    'user':               'root',
    'password':           '',
    'charset':            'utf8mb4',
    'connection_timeout': 300,
}
DB_NAME  = 'fraud_detection'
CSV_PATH = 'fraud_dataset_v5_full.csv'

CHUNK_SIZE = 5000   # rows per chunk — lower to 2000 if XAMPP still crashes
BATCH_SIZE = 50     # rows per INSERT — small to avoid packet issues
# ────────────────────────────────────────────────────

TABLES = {

'transactions': """
CREATE TABLE IF NOT EXISTS transactions (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id      VARCHAR(32)  NOT NULL UNIQUE,
    purchase_date       DATETIME(3)  NOT NULL,
    created             DATETIME(3),
    purchase_amount     DECIMAL(14,2),
    purchase_currency   VARCHAR(5),
    source_amount       DECIMAL(14,2),
    source_currency     VARCHAR(5),
    amount_inr          DECIMAL(14,2),
    card_number         VARCHAR(20),
    acquirer_bin        VARCHAR(10),
    issuer_country      VARCHAR(5),
    ip                  VARCHAR(45),
    ip_country          VARCHAR(60),
    ip_city             VARCHAR(60),
    ip_region           VARCHAR(60),
    ip_isp              VARCHAR(100),
    device_id           VARCHAR(64),
    cdn_device_id       VARCHAR(64),
    browser_ua          TEXT,
    device_type         VARCHAR(20),
    device_channel      VARCHAR(10),
    merchant_id         VARCHAR(30),
    merchant_category   VARCHAR(40),
    merchant_fraud_rate DECIMAL(6,4),
    mcc                 INT,
    merchant_country    VARCHAR(5),
    email               VARCHAR(120),
    mobile_no           VARCHAR(15),
    threeds_ind         VARCHAR(5),
    challenge_type      VARCHAR(30),
    auth_type           VARCHAR(40),
    acs_trans_id        VARCHAR(40),
    merchant_page_txn   TINYINT,
    profile_flags       VARCHAR(20),
    policy_engine_req   VARCHAR(20),
    suggestion          VARCHAR(10),
    velocity_5min       INT DEFAULT 0,
    velocity_1hr        INT DEFAULT 0,
    velocity_24hr       INT DEFAULT 0,
    device_cards_24h    INT DEFAULT 0,
    email_cards_total   INT DEFAULT 0,
    email_txn_count     INT DEFAULT 0,
    card_txn_24h        INT DEFAULT 0,
    f_high_amount               TINYINT DEFAULT 0,
    f_ip_issuer_mismatch        TINYINT DEFAULT 0,
    f_triple_country_mismatch   TINYINT DEFAULT 0,
    f_high_merchant_fraud_rate  TINYINT DEFAULT 0,
    f_new_account_high_value    TINYINT DEFAULT 0,
    f_threeds_failed            TINYINT DEFAULT 0,
    f_disposable_email          TINYINT DEFAULT 0,
    f_datacenter_ip             TINYINT DEFAULT 0,
    f_api_channel               TINYINT DEFAULT 0,
    f_bin_country_mismatch      TINYINT DEFAULT 0,
    f_merchant_page_redirect    TINYINT DEFAULT 0,
    risk_score          DECIMAL(10,4),
    risk_label          VARCHAR(20),
    is_fraud            TINYINT,
    scenario            VARCHAR(40),
    INDEX idx_card        (card_number),
    INDEX idx_device      (device_id),
    INDEX idx_email       (email),
    INDEX idx_date        (purchase_date),
    INDEX idx_fraud       (is_fraud),
    INDEX idx_card_date   (card_number, purchase_date),
    INDEX idx_device_date (device_id, purchase_date),
    INDEX idx_email_date  (email, purchase_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",

'fraud_cases': """
CREATE TABLE IF NOT EXISTS fraud_cases (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    case_id             VARCHAR(32) NOT NULL UNIQUE,
    transaction_id      VARCHAR(32) NOT NULL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    ml_probability      DECIMAL(6,4),
    calibrated_prob     DECIMAL(6,4),
    final_risk_score    DECIMAL(6,4),
    risk_band           VARCHAR(10),
    rules_triggered     TEXT,
    rule_adjustment     DECIMAL(6,4),
    shap_top5           TEXT,
    case_narrative      TEXT,
    disposition         VARCHAR(20),
    analyst_decision    VARCHAR(20),
    analyst_notes       TEXT,
    reviewed_at         DATETIME,
    reviewed_by         VARCHAR(60),
    status              VARCHAR(20) DEFAULT 'open',
    closed_at           DATETIME,
    INDEX idx_txn    (transaction_id),
    INDEX idx_band   (risk_band),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",

'audit_log': """
CREATE TABLE IF NOT EXISTS audit_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    event_time      DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    case_id         VARCHAR(32),
    transaction_id  VARCHAR(32),
    event_type      VARCHAR(40),
    actor           VARCHAR(60),
    payload         TEXT,
    INDEX idx_case (case_id),
    INDEX idx_time (event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""",

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
    last_computed       TIMESTAMP,
    txn_count_used      INT,
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
    detected_at         TIMESTAMP,
    anomaly_score       DECIMAL(6,4),
    INDEX idx_card (card_number),
    INDEX idx_device (device_id),
    INDEX idx_merchant (merchant_id),
    INDEX idx_pattern (pattern_type),
    INDEX idx_detected (detected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""
}

COL_MAP = {
    'transaction_id':                    'transaction_id',
    'purchase_date':                     'purchase_date',
    'created':                           'created',
    'purchase_amount':                   'purchase_amount',
    'purchase_currency_code':            'purchase_currency',
    'source_amount':                     'source_amount',
    'source_currency_code':              'source_currency',
    'amount_inr':                        'amount_inr',
    'card_number':                       'card_number',
    'acquirerBIN':                       'acquirer_bin',
    'issuerCountryCode':                 'issuer_country',
    'ip':                                'ip',
    'ip_country_long':                   'ip_country',
    'ip_city':                           'ip_city',
    'ip_region':                         'ip_region',
    'ip_isp':                            'ip_isp',
    'device_id':                         'device_id',
    'cdnDeviceId':                       'cdn_device_id',
    'browser_user_agent':                'browser_ua',
    'browser_device_type':               'device_type',
    'deviceChannel':                     'device_channel',
    'merchant_id':                       'merchant_id',
    'merchant_category':                 'merchant_category',
    'merchantFraudRate':                 'merchant_fraud_rate',
    'mcc':                               'mcc',
    'merchant_country':                  'merchant_country',
    'emailId':                           'email',
    'mobileNo':                          'mobile_no',
    'threeDSRequestorAuthenticationInd': 'threeds_ind',
    'challenge_type':                    'challenge_type',
    'authenticationType':                'auth_type',
    'acsTransID':                        'acs_trans_id',
    'merchantPageTxn':                   'merchant_page_txn',
    'profileFlags':                      'profile_flags',
    'policyEngineReq':                   'policy_engine_req',
    'suggestion':                        'suggestion',
    'velocity_5min_count':               'velocity_5min',
    'velocity_1hr_count':                'velocity_1hr',
    'velocity_24hr_count':               'velocity_24hr',
    'device_cards_24h':                  'device_cards_24h',
    'email_cards_total':                 'email_cards_total',
    'email_txn_count':                   'email_txn_count',
    'card_txn_24h':                      'card_txn_24h',
    'f_high_amount':                     'f_high_amount',
    'f_ip_issuer_mismatch':              'f_ip_issuer_mismatch',
    'f_triple_country_mismatch':         'f_triple_country_mismatch',
    'f_high_merchant_fraud_rate':        'f_high_merchant_fraud_rate',
    'f_new_account_high_value':          'f_new_account_high_value',
    'f_threeds_failed':                  'f_threeds_failed',
    'f_disposable_email':                'f_disposable_email',
    'f_datacenter_ip':                   'f_datacenter_ip',
    'f_api_channel':                     'f_api_channel',
    'f_bin_country_mismatch':            'f_bin_country_mismatch',
    'f_merchant_page_redirect':          'f_merchant_page_redirect',
    'risk_score':                        'risk_score',
    'risk_label':                        'risk_label',
    'is_fraud':                          'is_fraud',
    '_scenario':                         'scenario',
}


def create_schema(cursor):
    print("Creating database and tables...")
    cursor.execute(
        f"CREATE DATABASE IF NOT EXISTS {DB_NAME} "
        f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    )
    cursor.execute(f"USE {DB_NAME}")
    for name, ddl in TABLES.items():
        cursor.execute(ddl)
        print(f"  ✅ {name}")


def tune_session(cursor):
    """Bump session limits — prevents XAMPP dropping the connection mid-load."""
    cmds = [
        "SET SESSION net_write_timeout   = 300",
        "SET SESSION net_read_timeout    = 300",
        "SET SESSION wait_timeout        = 300",
        "SET SESSION interactive_timeout = 300",
    ]
    for cmd in cmds:
        try:
            cursor.execute(cmd)
        except Exception:
            pass
    # Needs SUPER privilege — skip silently if not available
    try:
        cursor.execute("SET GLOBAL max_allowed_packet = 67108864")
    except Exception:
        pass
    print("  ✅ Session tuned")


def prepare_dataframe(chunk_num=None):
    print(f"\nReading {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    print(f"  Total rows in CSV : {len(df):,}")

    if chunk_num is not None:
        start = (chunk_num - 1) * CHUNK_SIZE
        end   = min(start + CHUNK_SIZE, len(df))
        df    = df.iloc[start:end].copy()
        print(f"  Chunk {chunk_num}: rows {start}–{end-1} ({len(df)} rows)")

    df = df.rename(columns=COL_MAP)
    db_cols = list(COL_MAP.values())
    df = df[[c for c in db_cols if c in df.columns]]

    for col in ['purchase_date', 'created']:
        if col in df.columns:
            df[col] = (
                pd.to_datetime(df[col], format='ISO8601')
                .dt.strftime('%Y-%m-%d %H:%M:%S.%f')
                .str[:-3]
            )

    df = df.where(pd.notnull(df), None)
    return df


def load_transactions(conn, cursor, df):
    insert_cols  = [c for c in COL_MAP.values() if c in df.columns]
    placeholders = ', '.join(['%s'] * len(insert_cols))
    col_names    = ', '.join(insert_cols)
    sql          = f"INSERT IGNORE INTO transactions ({col_names}) VALUES ({placeholders})"

    total    = len(df)
    inserted = 0
    errors   = 0

    print(f"\nInserting {total:,} rows (batch size={BATCH_SIZE})...")

    for start in range(0, total, BATCH_SIZE):
        batch = df.iloc[start : start + BATCH_SIZE]
        rows  = [tuple(r) for _, r in batch.iterrows()]
        try:
            cursor.executemany(sql, rows)
            conn.commit()
            inserted += len(rows)
        except mysql.connector.Error as e:
            errors += len(rows)
            print(f"\n  ⚠ Batch error at row {start}: {e}")
            conn.rollback()
            # Row-by-row fallback so one bad row doesn't kill the batch
            for row in rows:
                try:
                    cursor.execute(sql, row)
                    conn.commit()
                    inserted += 1
                    errors   -= 1
                except Exception:
                    pass

        print(f"  {inserted:,}/{total:,} ({inserted/total*100:.0f}%)  errors={errors}", end='\r')

    print(f"\n  ✅ Inserted={inserted:,}  skipped/errored={errors}")


def verify(cursor):
    print("\nVerification:")
    cursor.execute("SELECT COUNT(*) FROM transactions")
    print(f"  Total rows   : {cursor.fetchone()[0]:,}")
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE is_fraud = 1")
    print(f"  Fraud rows   : {cursor.fetchone()[0]:,}")
    cursor.execute("SELECT MIN(purchase_date), MAX(purchase_date) FROM transactions")
    mn, mx = cursor.fetchone()
    print(f"  Date range   : {mn} → {mx}")


def main():
    chunk_num = None
    if '--chunk' in sys.argv:
        idx = sys.argv.index('--chunk')
        try:
            chunk_num = int(sys.argv[idx + 1])
            total_chunks = -(-20000 // CHUNK_SIZE)
            print(f"Chunk mode: {chunk_num}/{total_chunks}  (CHUNK_SIZE={CHUNK_SIZE})")
        except (IndexError, ValueError):
            print("Usage: python db_setup.py --chunk <number>")
            sys.exit(1)

    print("Connecting to MySQL...")
    conn   = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    create_schema(cursor)
    cursor.execute(f"USE {DB_NAME}")
    tune_session(cursor)

    df = prepare_dataframe(chunk_num)
    load_transactions(conn, cursor, df)
    verify(cursor)

    cursor.close()
    conn.close()

    if chunk_num is not None:
        total_chunks = -(-20000 // CHUNK_SIZE)
        if chunk_num < total_chunks:
            print(f"\n▶  Next: python db_setup.py --chunk {chunk_num + 1}")
        else:
            print("\n🎯 All chunks loaded. Run server.py next.")
    else:
        print("\n🎯 Database ready. Run server.py next.")


if __name__ == '__main__':
    main()