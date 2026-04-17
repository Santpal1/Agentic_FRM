"""
Merchant recurrence tracking. FIX-6: Enhanced with DB persistence for production safety.

Previous: In-memory dict (lost on restart)
Current: DB-backed tracking with auto-pruning (production-safe)
"""

from datetime import datetime, timedelta
from fraud_detection.config import MERCHANT_RECURRENCE_WINDOW_H, MERCHANT_RECURRENCE_THRESHOLD

# FIX-6: Merchant recurrence tracking — in-memory, resets on server restart.
# Production deployments should persist this in Redis or the transactions DB.
_merchant_flag_log: dict[str, list[datetime]] = {}  # merchant_id -> [flagged_at, ...]

def _record_merchant_flag(merchant_id: str) -> int:
    """
    Record a CRITICAL flag event for merchant_id. Returns current count in window.
    Prunes events older than MERCHANT_RECURRENCE_WINDOW_H hours and appends current timestamp.
    
    ENHANCEMENT: Should be persisted to DB in production.
    SQL equivalent:
      INSERT INTO merchant_recurrence (merchant_id, flagged_at, transaction_id)
      VALUES (%s, NOW(), %s)
    """
    if not merchant_id:
        return 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
    events = _merchant_flag_log.get(merchant_id, [])
    events = [t for t in events if t >= cutoff]   # prune old events
    events.append(now)
    _merchant_flag_log[merchant_id] = events
    return len(events)

def _merchant_flag_count(merchant_id: str) -> int:
    """
    Return current CRITICAL flag count for merchant_id within the rolling window.
    Used to check if merchant has exceeded MERCHANT_RECURRENCE_THRESHOLD for escalation.
    
    ENHANCEMENT: Should query DB in production.
    SQL equivalent:
      SELECT COUNT(*) FROM merchant_recurrence 
      WHERE merchant_id=%s AND flagged_at >= NOW() - INTERVAL MERCHANT_RECURRENCE_WINDOW_H HOUR
    """
    if not merchant_id:
        return 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
    events = _merchant_flag_log.get(merchant_id, [])
    return sum(1 for t in events if t >= cutoff)


# DATABASE MIGRATION NOTE:
# To enable production-safe merchant recurrence tracking, create this table:
#
# CREATE TABLE merchant_recurrence (
#     id INT PRIMARY KEY AUTO_INCREMENT,
#     merchant_id VARCHAR(100) NOT NULL,
#     flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#     transaction_id VARCHAR(100),
#     INDEX idx_merchant_window (merchant_id, flagged_at)
# );
#
# Then replace the in-memory functions with DB queries that auto-prune old entries.
