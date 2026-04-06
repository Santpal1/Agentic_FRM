"""
Tool: submit_false_positive_feedback (Stage 2 - Feedback Loop)
Flag a deny as a false positive and feed back to rule engine for analyst review.
FIX-10: rule_triggered must be one of the known rule names. Invalid names are rejected.
"""

from datetime import datetime
from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.rules_engine import KNOWN_RULE_NAMES

async def submit_false_positive_feedback(args):
    """
    STAGE 2 — Flag a deny as a false positive and feed back to rule engine.
    Call when a deny verdict is uncertain and correct disposition should have been accept_and_alert or accept_1fa.
    FIX-10: rule_triggered must be one of the known rule names. Invalid names are rejected.
    """
    tid      = args.get('transaction_id','unknown')
    orig     = args.get('original_disposition','deny')
    correct  = args.get('correct_disposition','accept_and_alert')
    rule     = args.get('rule_triggered','')
    note     = args.get('analyst_note','')

    if not rule:
        return [types.TextContent(type="text", text="rule_triggered is required")]

    # FIX-10: validate rule_triggered against the known rule names
    if rule not in KNOWN_RULE_NAMES:
        sorted_names = sorted(KNOWN_RULE_NAMES)
        return [types.TextContent(type="text", text=(
            f"ERROR: rule_triggered '{rule}' is not a known rule name.\n"
            f"Valid rule names:\n  " + "\n  ".join(sorted_names)
        ))]

    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO false_positive_feedback
            (transaction_id,original_disposition,correct_disposition,rule_triggered,analyst_note,created_at)
            VALUES (%s,%s,%s,%s,%s,%s)""",
            (tid,orig,correct,rule,note,datetime.utcnow()))
        db.commit(); fid=cur.lastrowid
    except Exception as e: saved=False; err=str(e); fid=0
    finally: cur.close(); db.close()

    out=(f"FALSE POSITIVE FEEDBACK LOGGED\n"
         f"================================\n"
         f"Transaction ID      : {tid}\n"
         f"Original disposition: {orig}\n"
         f"Correct disposition : {correct}\n"
         f"Rule over-triggered : {rule}\n"
         f"Analyst note        : {note or 'N/A'}\n"
         f"Persisted           : {'YES (ID='+str(fid)+')' if saved else 'NO -- '+err}\n"
         f"Timestamp           : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"--------------------------------\n"
         f"ACTION: Human analyst will review and update rule weight or add merchant exception.\n"
         f"================================")
    return [types.TextContent(type="text", text=out)]
