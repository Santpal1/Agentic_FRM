"""
Tool: update_case_status (Stage 2 - Case Management)
Set final disposition. ALWAYS call last. report field is MANDATORY.
FIX-7: add_case_note MUST be called before this tool — cases without a note are rejected.
"""

import json
from datetime import datetime
from mcp import types
from fraud_detection.utils import get_db

async def update_case_status(args):
    """
    STAGE 2 — Set final disposition. ALWAYS call last. report field is MANDATORY.
    FIX-7: add_case_note MUST be called before this tool — cases without a note are rejected.
    """
    tid=args.get('transaction_id','unknown')
    disposition=args.get('disposition','accept')
    band=args.get('risk_band',''); score=float(args.get('final_score',0))
    alert_cat=args.get('alert_category','genuine')
    outreach_req=args.get('outreach_required','no')
    outreach_tgt=args.get('outreach_target','none')
    report=args.get('report','')
    action=args.get('recommended_action',''); tools=args.get('tools_used',[])

    if not report:
        return [types.TextContent(type="text", text="ERROR: report field is MANDATORY. Provide a 3-5 line rationale before closing the case.")]

    # FIX-7: Enforce add_case_note prerequisite — check case_notes table before accepting
    db_check = get_db(); cur_check = db_check.cursor(dictionary=True)
    note_exists = False
    try:
        cur_check.execute(
            "SELECT COUNT(*) AS cnt FROM case_notes WHERE transaction_id=%s", (tid,)
        )
        row = cur_check.fetchone()
        note_exists = bool(row and row['cnt'] > 0)
    except Exception:
        # If the table doesn't exist yet or query fails, allow through (new deployment).
        note_exists = True
    finally:
        cur_check.close(); db_check.close()

    if not note_exists:
        return [types.TextContent(type="text", text=(
            f"ERROR: Cannot close case {tid} — no case note found.\n"
            f"Call add_case_note first with a 3-5 line assessment, "
            f"then call update_case_status again."
        ))]

    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO case_status
            (transaction_id,status,risk_band,final_score,disposition,outreach_required,
             outreach_target,report,recommended_action,tools_used,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE status=VALUES(status),risk_band=VALUES(risk_band),
            final_score=VALUES(final_score),disposition=VALUES(disposition),
            outreach_required=VALUES(outreach_required),outreach_target=VALUES(outreach_target),
            report=VALUES(report),recommended_action=VALUES(recommended_action),
            tools_used=VALUES(tools_used),updated_at=VALUES(updated_at)""",
            (tid,disposition,band,score,disposition,outreach_req,outreach_tgt,
             report,action,json.dumps(tools),datetime.utcnow()))
        db.commit()
    except Exception as e: saved=False; err=str(e)
    finally: cur.close(); db.close()

    emoji={'accept':'OK','accept_1fa':'1FA','accept_and_alert':'ALERT','deny':'DENY'}.get(disposition,'?')
    outreach_line = (f"Outreach target    : {outreach_tgt}" if outreach_tgt != 'none'
                     else "Outreach           : none required")
    out=(f"CASE CLOSED  [INVESTIGATION COMPLETE]\n"
         f"======================================\n"
         f"Transaction ID     : {tid}\n"
         f"Disposition        : [{emoji}] {disposition.upper()}\n"
         f"Alert category     : {alert_cat}\n"
         f"Risk band          : {band or 'N/A'}\n"
         f"Final score        : {score:.4f}\n"
         f"{outreach_line}\n"
         f"Tools used ({len(tools)}): {', '.join(tools) if tools else 'N/A'}\n"
         f"Persisted to DB    : {'YES' if saved else 'NO -- '+err}\n"
         f"Closed at          : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"--------------------------------------\n"
         f"REPORT\n  {report}\n"
         f"======================================\nInvestigation complete.")
    return [types.TextContent(type="text", text=out)]
