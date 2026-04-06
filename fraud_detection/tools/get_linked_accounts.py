"""
Tool: get_linked_accounts (Stage 2 - Cross-identifier Fraud Ring Detection)
Finds accounts sharing any identifier: IP, device_id, email domain, card BIN prefix.
"""

from datetime import timedelta, datetime
from mcp import types
from fraud_detection.utils import get_db

async def get_linked_accounts(args):
    """
    STAGE 2 — Cross-identifier fraud ring detection.
    Finds accounts sharing any identifier: same IP, device_id, email domain (non-generic), card BIN prefix.
    Returns: linked accounts, shared identifier type, fraud rates, ring_score.
    """
    card=args.get('card',''); did=args.get('device_id','')
    email=args.get('email',''); ip=args.get('ip','')
    hours=int(args.get('hours',720))
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        since=(datetime.utcnow()-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        bin6=str(card)[:6] if card else ''
        domain=email.split('@')[-1] if '@' in email else ''
        generic=('gmail.com','yahoo.com','hotmail.com','outlook.com','rediffmail.com')
        queries=[]
        if did:  queries.append(("same_device_id","device_id=%s",did))
        if ip:   queries.append(("same_ip","ip=%s",ip))
        if bin6: queries.append(("same_bin_prefix","LEFT(card_number,6)=%s",bin6))
        if domain and domain not in generic:
            queries.append(("same_email_domain","email LIKE %s",f"%@{domain}"))
        all_linked=[]
        for ltype, cond, val in queries:
            cur.execute(f"""SELECT DISTINCT card_number,email,device_id,ip,
                COUNT(*) AS txns,SUM(is_fraud) AS ft,AVG(is_fraud) AS fr,MAX(purchase_date) AS ls
                FROM transactions WHERE {cond} AND purchase_date>=%s
                  AND (card_number!=%s OR %s='')
                GROUP BY card_number,email,device_id,ip ORDER BY ft DESC LIMIT 20""",
                (val,since,card or '',card or ''))
            for r in cur.fetchall(): r['link_type']=ltype; all_linked.append(r)
        if not all_linked:
            return [types.TextContent(type="text", text="No linked accounts found in the lookback window.")]
        tot_f=sum(int(r['ft'] or 0) for r in all_linked)
        tot_t=sum(int(r['txns']) for r in all_linked)
        rs=round(tot_f/max(tot_t,1),3)
        lines=[f"LINKED ACCOUNTS REPORT  [STAGE 2]","="*60,
               f"Lookback         : {hours}h",f"Linked accounts  : {len(all_linked)}",
               f"Ring fraud score : {rs:.3f}  {'[!] HIGH — coordinated fraud likely' if rs>0.3 else '[ok]'}",""]
        for r in all_linked:
            lines.append(f"  [{r['link_type']}]  card={str(r['card_number'])[:6]}xx  "
                         f"email={str(r['email'])[:25]}  txns={r['txns']}  "
                         f"fraud={float(r['fr'] or 0)*100:.0f}%  last={str(r['ls'])[:10]}")
        lines+=["","SUGGESTED NEXT TOOLS",
                f"  {'get_ip_intelligence (multiple linked accounts)' if rs>0.3 else 'none — proceed to add_case_note + update_case_status'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
