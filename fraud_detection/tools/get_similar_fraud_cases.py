"""
Tool: get_similar_fraud_cases (Stage 2 - Top-N Similar Fraud Cases)
Matches on binary flags, auth type, device channel, IP country, amount range.
Helps identify if case matches known ongoing fraud campaign.
"""

from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.flags import compute_flags

async def get_similar_fraud_cases(args):
    """
    STAGE 2 — Top-N most similar confirmed fraud cases from history.
    Matches on binary flags, auth type, device channel, IP country, amount range.
    Call when: unusual signal combination, grey zone MEDIUM band, need historical precedent.
    """
    txn=compute_flags(dict(args.get("transaction",{}))); top_n=int(args.get('top_n',5))
    fraud_only=args.get('fraud_only',True); sf=args.get('scenario_filter','')
    amt=float(txn.get('amount_inr') or txn.get('purchase_amount') or 0)
    auth=str(txn.get('authenticationType') or ''); dch=str(txn.get('deviceChannel') or '')
    ipc=str(txn.get('ip_country_long') or '')
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        fc="AND is_fraud=1" if fraud_only else ""
        sc=f"AND scenario LIKE '%{sf}%'" if sf else ""
        cur.execute(f"""SELECT transaction_id,purchase_date,amount_inr,merchant_country,
            ip_country,auth_type,device_channel,risk_score,risk_label,is_fraud,scenario,
            f_triple_country_mismatch,f_threeds_failed,f_disposable_email,f_api_channel,
            f_new_account_high_value,
            ((f_triple_country_mismatch={int(txn.get('f_triple_country_mismatch',0))})*3+
             (f_threeds_failed={int(txn.get('f_threeds_failed',0))})*3+
             (f_disposable_email={int(txn.get('f_disposable_email',0))})*2+
             (f_api_channel={int(txn.get('f_api_channel',0))})*2+
             (f_new_account_high_value={int(txn.get('f_new_account_high_value',0))})*2+
             (auth_type=%s)*2+(device_channel=%s)*1+(ip_country=%s)*1) AS sim
            FROM transactions WHERE amount_inr BETWEEN %s AND %s {fc} {sc}
            ORDER BY sim DESC,purchase_date DESC LIMIT %s""",
            (auth,dch,ipc,amt*0.5,amt*2.0,top_n*3))
        rows=cur.fetchall()
        if not rows: return [types.TextContent(type="text", text="No similar fraud cases found.")]
        seen=set(); uniq=[]
        for r in rows:
            k=(r['scenario'],r['auth_type'],r['device_channel'])
            if k not in seen: seen.add(k); uniq.append(r)
            if len(uniq)>=top_n: break
        lines=[f"SIMILAR FRAUD CASES  [STAGE 2]","="*60,
               f"Query: amt≈Rs.{amt:,.0f}  auth={auth}  channel={dch}",
               f"Matched: {len(uniq)} cases",""]
        for i,r in enumerate(uniq,1):
            flags=[k for k,v in [('triple_mismatch',r['f_triple_country_mismatch']),
                                  ('3ds_fail',r['f_threeds_failed']),
                                  ('disposable',r['f_disposable_email']),
                                  ('api',r['f_api_channel'])] if v]
            lines+=[f"  Case {i}: {str(r['purchase_date'])[:10]}  Rs.{float(r['amount_inr'] or 0):>10,.0f}",
                    f"    Scenario  : {r['scenario'] or 'untagged'}",
                    f"    Auth/Chan : {r['auth_type']} / {r['device_channel']}",
                    f"    IP country: {r['ip_country']}",
                    f"    Risk      : {float(r['risk_score'] or 0):.1f}  [{r['risk_label']}]",
                    f"    Flags     : {', '.join(flags) if flags else 'none'}",
                    f"    Similarity: {r['sim']}/14",""]
        lines+=["ANALYST GUIDANCE",
                "  Matching scenario tags → high confidence in that classification.",
                "  Divergent scenarios → call get_customer_profile for more context."]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
