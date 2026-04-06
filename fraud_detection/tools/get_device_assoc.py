"""
Tool: get_device_assoc (Stage 2 - Device Association Report)
Returns all cards and emails linked to this device, fraud rates, ring signal.
"""

from datetime import timedelta, datetime
from mcp import types
from fraud_detection.utils import get_db

async def get_device_assoc(args):
    """
    STAGE 2 — Device association report.
    Call for CRITICAL band, API channel, or when profile/recent_txns suggest multi-card usage.
    Returns: all cards and emails linked to this device, fraud rates, ring signal.
    """
    did=args.get('device_id'); hours=int(args.get('hours',168))
    if not did: return [types.TextContent(type="text", text="device_id is required")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        since=(datetime.utcnow()-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""SELECT COUNT(*) AS tot, COUNT(DISTINCT card_number) AS uc,
            COUNT(DISTINCT email) AS ue, SUM(is_fraud) AS ft, AVG(is_fraud) AS fr,
            MIN(purchase_date) AS fs, MAX(purchase_date) AS ls, MAX(velocity_5min) AS pv
            FROM transactions WHERE device_id=%s AND purchase_date>=%s""",(did,since))
        s=cur.fetchone()
        cur.execute("""SELECT card_number,COUNT(*) AS txns,SUM(is_fraud) AS fraud,MAX(purchase_date) AS lu
            FROM transactions WHERE device_id=%s AND purchase_date>=%s
            GROUP BY card_number ORDER BY txns DESC LIMIT 20""",(did,since))
        cards=cur.fetchall()
        cur.execute("""SELECT email,COUNT(*) AS txns,SUM(is_fraud) AS fraud,MAX(f_disposable_email) AS disp
            FROM transactions WHERE device_id=%s AND purchase_date>=%s
            GROUP BY email ORDER BY txns DESC LIMIT 10""",(did,since))
        emails=cur.fetchall()
        uc=s['uc'] or 0; ue=s['ue'] or 0; fr=float(s['fr'] or 0)*100; ring=uc>=5 or ue>=3
        next_t=[]
        if uc>=5: next_t.append("get_linked_accounts (high card count — fraud ring likely)")
        if ring:  next_t.append("get_ip_intelligence (ring signal detected)")
        lines=[f"DEVICE ASSOCIATION REPORT  [STAGE 2]","="*60,
               f"Device ID        : {did}", f"Lookback         : {hours}h",
               f"Fraud ring signal: {'[!] YES — HIGH RISK' if ring else '[ok] no'}","",
               f"SUMMARY",f"  Total txns   : {s['tot']}",
               f"  Unique cards : {uc}   {'[!] HIGH' if uc>=5 else '[ok]'}",
               f"  Unique emails: {ue}   {'[!] HIGH' if ue>=3 else '[ok]'}",
               f"  Fraud rate   : {fr:.1f}%", f"  Peak velocity: {s['pv']} txns/5min",
               f"  First seen   : {s['fs']}", f"  Last seen    : {s['ls']}", "",
               f"ASSOCIATED CARDS ({len(cards)})"]
        for c in cards:
            lines.append(f"  {str(c['card_number'])[:6]}xxxxxx  txns={c['txns']}  fraud={int(c['fraud'] or 0)}  last={str(c['lu'])[:10]}")
        lines+=["",f"ASSOCIATED EMAILS ({len(emails)})"]
        for e in emails:
            lines.append(f"  {e['email']}{'  [DISPOSABLE]' if e['disp'] else ''}  txns={e['txns']}  fraud={int(e['fraud'] or 0)}")
        lines+=["","SUGGESTED NEXT TOOLS",
                f"  {(chr(10)+'  ').join(next_t) if next_t else 'none — proceed to add_case_note + update_case_status'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
