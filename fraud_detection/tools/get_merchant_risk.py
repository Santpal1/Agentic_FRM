"""
Tool: get_merchant_risk (Stage 2 - Merchant Fraud Intelligence)
Returns historical fraud rate, 30-day fraud rate, failure rate vs MCC average, watchlist status.
FIX-6: Also auto-triggered when merchant accumulates >= 3 CRITICAL flags in 24h.
"""

from datetime import timedelta, datetime
from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.merchant_tracking import get_merchant_flag_count
from fraud_detection.config import MERCHANT_RECURRENCE_THRESHOLD, MERCHANT_RECURRENCE_WINDOW_H

async def get_merchant_risk(args):
    """
    STAGE 2 — Merchant fraud intelligence and MCC peer comparison.
    Returns: historical fraud rate, last 30-day fraud rate, failure rate vs MCC average, watchlist status.
    FIX-6: Also auto-triggered when merchant accumulates >= 3 CRITICAL flags in 24h.
    """
    mc=args.get('merchant_country',''); mid=args.get('merchant_id','')
    mcat=args.get('merchant_category',''); mfr=float(args.get('merchantFraudRate',0))
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        conds,params=[],[]
        if mid:  conds.append("merchant_id=%s"); params.append(mid)
        if mc:   conds.append("merchant_country=%s"); params.append(mc)
        if mcat: conds.append("merchant_category=%s"); params.append(mcat)
        ms=None
        if conds:
            cur.execute(f"""SELECT COUNT(*) AS tt,SUM(is_fraud) AS ft,AVG(is_fraud) AS fr,
                AVG(amount_inr) AS aa,COUNT(DISTINCT card_number) AS uc,
                MIN(purchase_date) AS fs,MAX(purchase_date) AS ls
                FROM transactions WHERE {' AND '.join(conds)}""",params)
            ms=cur.fetchone()
        ca=None
        if mcat:
            cur.execute("SELECT AVG(is_fraud) AS cfr,COUNT(*) AS ct FROM transactions WHERE merchant_category=%s",(mcat,))
            ca=cur.fetchone()
        since30=(datetime.utcnow()-timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        rs30=None
        if conds:
            cur.execute(f"""SELECT COUNT(*) AS t30,SUM(is_fraud) AS f30,AVG(is_fraud) AS fr30
                FROM transactions WHERE {' AND '.join(conds)} AND purchase_date>=%s""",params+[since30])
            rs30=cur.fetchone()
        hfr=float(ms['fr'] or 0)*100 if ms else None
        rfr=float(rs30['fr30'] or 0)*100 if rs30 else None
        cfr=float(ca['cfr'] or 0)*100 if ca else None
        wl=mfr>0.15 or (hfr or 0)>15 or (rfr or 0)>20
        spike=rfr is not None and hfr is not None and rfr>hfr*1.5
        # FIX-6: include recurrence count in merchant risk report
        recurrence_count = get_merchant_flag_count(mid)
        recurrence_line = (
            f"\n  Recurrence (24h) : {recurrence_count} CRITICAL flags  [!] ELEVATED"
            if recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD else ""
        )
        lines=[f"MERCHANT RISK PROFILE  [STAGE 2]","="*60,
               f"Merchant country  : {mc or 'N/A'}",f"Merchant category : {mcat or 'N/A'}",
               f"Watchlist status  : {'[!] YES — HIGH RISK' if wl else '[ok] not flagged'}",
               recurrence_line, "",
               f"FRAUD RATES",f"  Payload reported  : {mfr*100:.1f}%",
               f"  Historical        : {f'{hfr:.1f}%' if hfr is not None else 'N/A'}",
               f"  Last 30 days      : {f'{rfr:.1f}%' if rfr is not None else 'N/A'}{'  [!] SPIKE' if spike else ''}",
               f"  Category peer avg : {f'{cfr:.1f}%' if cfr is not None else 'N/A'}"]
        if ms:
            lines+=[f"","HISTORY",f"  Total txns   : {ms['tt']}",
                    f"  Unique cards : {ms['uc']}",f"  Avg amount   : Rs.{float(ms['aa'] or 0):,.0f}"]
        verdict=("ESCALATE — merchant watchlisted." if wl else
                 "MONITOR — elevated but below watchlist." if mfr>0.05 else
                 "LOW RISK — within normal range.")
        lines+=["",f"ANALYST GUIDANCE: {verdict}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
