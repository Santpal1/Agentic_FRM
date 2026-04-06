"""
Tool: add_case_note (Stage 2 - Case Management)
Append structured case report. MANDATORY before update_case_status.
FIX-2: Hard limit of 400 characters max. Submissions over 400 chars are REJECTED.
"""

from datetime import datetime
from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.config import CASE_NOTE_MAX_CHARS

async def add_case_note(args):
    """
    STAGE 2 — Append structured case report. MANDATORY before update_case_status.
    FIX-2: Hard limit of 400 characters max. Submissions over 400 chars are REJECTED.
    """
    tid=args.get('transaction_id','unknown'); ntype=args.get('note_type','final_verdict')
    content=args.get('content',''); band=args.get('risk_band','UNKNOWN')
    alert_cat=args.get('alert_category','genuine'); conf=float(args.get('confidence',0.0))

    if not content:
        return [types.TextContent(type="text", text="ERROR: content is required.")]

    # FIX-2: Hard cap enforcement
    if len(content) > CASE_NOTE_MAX_CHARS:
        over = len(content) - CASE_NOTE_MAX_CHARS
        return [types.TextContent(type="text", text=(
            f"ERROR: Case note rejected — content is {len(content)} chars, "
            f"{over} over the {CASE_NOTE_MAX_CHARS}-char hard limit.\n"
            f"Rewrite as 3-5 tight lines totalling ≤{CASE_NOTE_MAX_CHARS} chars. "
            f"3 lines are sufficient for straightforward cases; use up to 5 only if needed.\n"
            f"Template:\n"
            f"  L1: [rule] fired — [why]\n"
            f"  L2: [other signals checked]\n"
            f"  L3: [merchant context]\n"
            f"  L4: [verdict + confidence]\n"
            f"  L5 (optional): [action + outreach target]"
        ))]

    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO case_notes (transaction_id,note_type,content,risk_band,confidence,created_at)
            VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE content=VALUES(content),
            risk_band=VALUES(risk_band),confidence=VALUES(confidence),created_at=VALUES(created_at)""",
            (tid,ntype,content,band,conf,datetime.utcnow()))
        db.commit(); nid=cur.lastrowid
    except Exception as e: saved=False; err=str(e); nid=0
    finally: cur.close(); db.close()

    out=(f"CASE NOTE ADDED  [STAGE 2]\n===========================\n"
         f"Transaction ID : {tid}\nNote type      : {ntype}\n"
         f"Alert category : {alert_cat}\nRisk band      : {band}\nConfidence     : {conf:.0%}\n"
         f"Length         : {len(content)}/{CASE_NOTE_MAX_CHARS} chars\n"
         f"Persisted      : {'YES (ID='+str(nid)+')' if saved else 'NO -- '+err}\n"
         f"Timestamp      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"===========================")
    return [types.TextContent(type="text", text=out)]
