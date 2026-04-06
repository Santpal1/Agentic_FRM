"""
Tool: get_recent_txns (Stage 2 - Recent Transaction History)
Returns recent transactions on card/device/email with fraud labels and risk scores.
Watch for excess failure rate, repeat same-amount transactions, rapid IP change.
"""

from datetime import timedelta, datetime
from mcp import types
from fraud_detection.utils import get_db

async def get_recent_txns(args):
    """
    STAGE 2 — Recent transaction history on card/device/email.
    Call for HIGH+ bands, or when velocity rules fired, or when profile shows elevated fraud rate.
    Returns: last N transactions with amounts, merchants, timestamps, fraud labels, risk scores.
    """
    card=args.get('card'); did=args.get('device_id'); email=args.get('email')
    limit=int(args.get('limit',20)); hours=int(args.get('hours',72))
    if not any([card,did,email]):
        return [types.TextContent(type="text", text="Provide at least one of: card, device_id, email")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        since=(datetime.utcnow()-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        conds,params=["purchase_date>=%s"],[since]
        if card:  conds.append("card_number=%s"); params.append(card)
        if did:   conds.append("device_id=%s");   params.append(did)
        if email: conds.append("email=%s");        params.append(email)
        cur.execute(f"""SELECT transaction_id,purchase_date,amount_inr,merchant_category,
            merchant_country,ip_country,auth_type,device_channel,risk_score,risk_label,
            is_fraud,scenario,f_disposable_email,f_threeds_failed,f_datacenter_ip,f_api_channel
            FROM transactions WHERE {' AND '.join(conds)} ORDER BY purchase_date DESC LIMIT %s""",
            params+[limit])
        rows=cur.fetchall()
        if not rows:
            return [types.TextContent(type="text", text=f"No transactions found in the last {hours}h.")]
        fc=sum(1 for r in rows if r['is_fraud'])
        lines=[f"RECENT TRANSACTIONS (last {hours}h, {len(rows)} shown)  [STAGE 2]",
               "="*60, f"Fraud in window: {fc}/{len(rows)} ({fc/len(rows)*100:.0f}%)", ""]
        for r in rows:
            flags=[k for k,v in [('disposable',r['f_disposable_email']),('3ds_fail',r['f_threeds_failed']),
                                  ('datacenter',r['f_datacenter_ip']),('api',r['f_api_channel'])] if v]
            lines.append(f"  {str(r['purchase_date'])[:19]}  Rs.{float(r['amount_inr'] or 0):>10,.0f}"
                         f"  {str(r['merchant_category']):<18} {str(r['ip_country']):<12}"
                         f"  [{r['risk_label']}]{'  [FRAUD]' if r['is_fraud'] else ''}")
            if flags: lines.append(f"    flags: {' | '.join(flags)}")
        burst=fc>3; multi_c=len(set(r['merchant_country'] for r in rows))>2
        next_t=[]
        if burst:   next_t.append("get_device_assoc (velocity burst)")
        if multi_c: next_t.append("get_linked_accounts (multi-country pattern)")
        lines+=["",f"SUGGESTED NEXT TOOLS",
                f"  {(chr(10)+'  ').join(next_t) if next_t else 'none — proceed to add_case_note + update_case_status'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
