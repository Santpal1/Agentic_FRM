"""
Merchant recurrence tracking. FIX-6: In-memory dict tracking CRITICAL flags per merchant for escalation.
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
    """
    if not merchant_id:
        return 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
    events = _merchant_flag_log.get(merchant_id, [])
    return sum(1 for t in events if t >= cutoff)
