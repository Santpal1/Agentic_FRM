"""
Tool: get_customer_profile (Stage 2 - Customer Risk Profile)
Returns transaction history, fraud rate, failure rate, same-amount repeat detection, linked identifiers.
"""

from datetime import timedelta, datetime
from mcp import types
from fraud_detection.utils import get_db

async def get_customer_profile(args):
    """
    STAGE 2 — Customer risk profile. Call for MEDIUM+ bands.
    Returns: transaction history, fraud rate, failure rate, same-amount repeat detection,
    linked cards/devices/emails, velocity stats, known scenarios.
    """
    email=args.get('email'); card=args.get('card'); did=args.get('device_id')
    if not any([email,card,did]):
        return [types.TextContent(type="text", text="Provide at least one of: email, card, device_id")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        conds,params=[],[]
        if email: conds.append("email=%s"); params.append(email)
        if card:  conds.append("card_number=%s"); params.append(card)
        if did:   conds.append("device_id=%s"); params.append(did)
        cur.execute(f"""SELECT COUNT(*) AS tt, SUM(is_fraud) AS ft, AVG(is_fraud) AS fr,
            MIN(purchase_date) AS fs, MAX(purchase_date) AS ls,
            COUNT(DISTINCT card_number) AS uc, COUNT(DISTINCT device_id) AS ud,
            COUNT(DISTINCT email) AS ue, AVG(amount_inr) AS aa, MAX(amount_inr) AS ma,
            MAX(email_cards_total) AS mc, MAX(velocity_5min) AS mv5, MAX(velocity_24hr) AS mv24,
            MAX(f_disposable_email) AS disp, GROUP_CONCAT(DISTINCT scenario) AS scen
            FROM transactions WHERE {' OR '.join(conds)}""", params)
        row=cur.fetchone()
        if not row or not row['tt']:
            # FIX-8: explicit no-records guidance so caller knows to fall back
            return [types.TextContent(type="text", text=(
                "No records found for the provided identifier(s).\n"
                "FIX-8 FALLBACK: If this is a CRITICAL transaction, call get_recent_txns with "
                "the card number alone before issuing a verdict. Do not skip to disposition."
            ))]
        fr=float(row['fr'] or 0)*100; rl='HIGH' if fr>30 else('MEDIUM' if fr>10 else 'LOW')
        uc=row['uc'] or 0; mc=row['mc'] or 0
        next_t=[]
        if fr>30 or uc>3: next_t.append("get_linked_accounts")
        if uc>3:          next_t.append("get_device_assoc")
        if row['scen'] and any(s in str(row['scen']) for s in ['card_testing','api_bot_attack']):
            if "get_device_assoc" not in next_t: next_t.append("get_device_assoc")
        out = f"""CUSTOMER PROFILE  [STAGE 2]
============================
Identifier(s)    : {', '.join(filter(None,[email,card,did]))}
Risk level       : {rl}

TRANSACTION HISTORY
  Total txns     : {row['tt']}
  Fraud txns     : {int(row['ft'] or 0)}  ({fr:.1f}% fraud rate)
  First seen     : {row['fs']}    Last seen : {row['ls']}
  Avg amount     : Rs.{float(row['aa'] or 0):,.2f}
  Max amount     : Rs.{float(row['ma'] or 0):,.2f}

LINKAGE SIGNALS
  Unique cards   : {uc}   {'[!] HIGH — possible card testing' if uc>3 else '[ok]'}
  Unique devices : {row['ud']}
  Unique emails  : {row['ue']}
  Max email→cards: {mc}   {'[!] HIGH — possible account farming' if mc>5 else '[ok]'}
  Disposable email: {'YES [!]' if row['disp'] else 'no'}

VELOCITY (historical peak)
  Max 5-min burst: {row['mv5']}    Max 24hr: {row['mv24']}

SCENARIOS SEEN
  {row['scen'] or 'none recorded'}

SUGGESTED NEXT TOOLS
  {' + '.join(next_t) if next_t else 'none — proceed to add_case_note + update_case_status'}
============================"""
        return [types.TextContent(type="text", text=out)]
    finally: cur.close(); db.close()
