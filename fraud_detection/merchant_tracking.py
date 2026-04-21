"""
Merchant recurrence tracking. DB-backed for production safety.
FIX-6: Fully migrated from in-memory to persistent database storage.
"""

from datetime import datetime, timedelta
from fraud_detection.config import MERCHANT_RECURRENCE_WINDOW_H, MERCHANT_RECURRENCE_THRESHOLD
from fraud_detection.utils import get_db

def record_merchant_flag(merchant_id: str, transaction_id: str = '', 
                         merchant_name: str = '', risk_band: str = '', reason: str = '') -> int:
    """
    Record a CRITICAL flag event for merchant_id in the database.
    Returns current count of CRITICAL flags in the rolling window.
    
    Automatically prunes events older than MERCHANT_RECURRENCE_WINDOW_H hours.
    
    Args:
        merchant_id: Merchant identifier
        transaction_id: Transaction that triggered the flag
        merchant_name: Merchant name for reference
        risk_band: Risk band (CRITICAL, HIGH, etc.)
        reason: Reason for flagging (for investigation)
    
    Returns:
        Count of CRITICAL flags within the rolling window
    """
    if not merchant_id:
        return 0
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        # Insert new flag record
        cur.execute("""
            INSERT INTO merchant_recurrence 
            (merchant_id, merchant_name, transaction_id, risk_band, reason, flagged_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (merchant_id, merchant_name, transaction_id, risk_band, reason))
        db.commit()
        
        # Count flags in rolling window
        cutoff = datetime.utcnow() - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
        cur.execute("""
            SELECT COUNT(*) as cnt FROM merchant_recurrence
            WHERE merchant_id=%s AND flagged_at >= %s
        """, (merchant_id, cutoff.strftime('%Y-%m-%d %H:%M:%S')))
        result = cur.fetchone()
        return result['cnt'] if result else 0
    finally:
        cur.close()
        db.close()

def get_merchant_flag_count(merchant_id: str) -> int:
    """
    Return current CRITICAL flag count for merchant_id within the rolling window.
    Used to check if merchant has exceeded MERCHANT_RECURRENCE_THRESHOLD for escalation.
    
    Returns:
        Count of flags within the rolling window
    """
    if not merchant_id:
        return 0
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cutoff = datetime.utcnow() - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
        cur.execute("""
            SELECT COUNT(*) as cnt FROM merchant_recurrence
            WHERE merchant_id=%s AND flagged_at >= %s
        """, (merchant_id, cutoff.strftime('%Y-%m-%d %H:%M:%S')))
        result = cur.fetchone()
        return result['cnt'] if result else 0
    finally:
        cur.close()
        db.close()

def get_merchant_recurrence_details(merchant_id: str, limit: int = 10) -> list:
    """
    Fetch recent CRITICAL flags for a merchant within the rolling window.
    Useful for investigation and pattern detection.
    
    Returns:
        List of dicts with flag details (flagged_at, transaction_id, risk_band, reason)
    """
    if not merchant_id:
        return []
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cutoff = datetime.utcnow() - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
        cur.execute("""
            SELECT transaction_id, risk_band, reason, flagged_at
            FROM merchant_recurrence
            WHERE merchant_id=%s AND flagged_at >= %s
            ORDER BY flagged_at DESC
            LIMIT %s
        """, (merchant_id, cutoff.strftime('%Y-%m-%d %H:%M:%S'), limit))
        return cur.fetchall()
    finally:
        cur.close()
        db.close()

def prune_old_merchant_flags(older_than_hours: int = None):
    """
    Remove merchant recurrence records older than specified hours.
    Default uses MERCHANT_RECURRENCE_WINDOW_H * 2 for safekeeping.
    
    Useful for scheduled cleanup jobs.
    """
    if older_than_hours is None:
        older_than_hours = MERCHANT_RECURRENCE_WINDOW_H * 2
    
    db = get_db()
    cur = db.cursor()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)
        cur.execute("""
            DELETE FROM merchant_recurrence
            WHERE flagged_at < %s
        """, (cutoff.strftime('%Y-%m-%d %H:%M:%S'),))
        deleted = cur.rowcount
        db.commit()
        return deleted
    finally:
        cur.close()
        db.close()
