"""
Tool: get_merchant_onboarding (Stage 2 - Merchant Onboarding Context)
Returns merchant type, onboarding date, website URL, MCC code, known_brand flag, trust_tier.
FIX-5: This tool is now included in Stage 1 suggested_tools for every FLAGGED transaction.
"""

from mcp import types
from fraud_detection.utils import get_db
from fraud_detection.rules_engine import get_merchant_trust_tier

async def get_merchant_onboarding(args):
    """
    STAGE 2 — Merchant onboarding context. ALWAYS call before final disposition.
    Returns: merchant type, onboarding date, website URL, MCC code, known_brand flag, trust_tier.
    FIX-5: This tool is now included in Stage 1 suggested_tools for every FLAGGED transaction.
    """
    mid   = args.get('merchant_id','')
    mname = args.get('merchant_name','')
    mc    = args.get('merchant_country','')
    mcc   = args.get('mcc_code','')
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        row = None
        if mid:
            cur.execute("SELECT * FROM merchant_onboarding WHERE merchant_id=%s",(mid,))
            row = cur.fetchone()
        if not row and mname:
            cur.execute("SELECT * FROM merchant_onboarding WHERE merchant_name LIKE %s",(f'%{mname}%',))
            row = cur.fetchone()
        if row:
            trust_tier   = row.get('trust_tier','registered')
            known_brand  = bool(row.get('known_brand',0))
            merchant_type= row.get('merchant_type','unknown')
            onboard_date = str(row.get('onboarding_date','N/A'))
            website      = row.get('website_url','N/A')
            mcc_code     = row.get('mcc_code', mcc or 'N/A')
            db_found     = True
        else:
            trust_tier   = get_merchant_trust_tier(mname, mid)
            known_brand  = trust_tier == 'known_brand'
            merchant_type= 'unknown — not in onboarding DB'
            onboard_date = 'N/A'
            website      = 'N/A'
            mcc_code     = mcc or 'N/A'
            db_found     = False

        disp_impact = {
            'known_brand': 'DENY BLOCKED — max disposition is accept_and_alert unless CRITICAL + confirmed ring.',
            'registered':  'Standard disposition logic applies. No special protection.',
            'unknown':     'ELEVATED RISK — treat as unknown merchant. Lean toward deny for HIGH+ band.',
        }.get(trust_tier, 'unknown')

        high_value_normal = any(k in (merchant_type or '').lower()
                                for k in ['jewel','gold','electron','travel','luxury','airline'])
        amt_context = ("High-value transactions are NORMAL for this merchant type — weight accordingly."
                       if high_value_normal else
                       "High-value transactions warrant additional scrutiny for this merchant type.")

        lines = [f"MERCHANT ONBOARDING  [STAGE 2]","="*60,
                 f"Merchant ID      : {mid or 'N/A'}",
                 f"Merchant name    : {mname or 'N/A'}",
                 f"Merchant type    : {merchant_type}",
                 f"MCC code         : {mcc_code}",
                 f"Country          : {mc or 'N/A'}",
                 f"Onboarding date  : {onboard_date}",
                 f"Website URL      : {website}",
                 f"Known brand      : {'YES' if known_brand else 'no'}",
                 f"Trust tier       : {trust_tier.upper()}",
                 f"Found in DB      : {'YES' if db_found else 'NO — fallback to name heuristic'}",
                 "",
                 f"DISPOSITION IMPACT",
                 f"  {disp_impact}",
                 "",
                 f"AMOUNT CONTEXT",
                 f"  {amt_context}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()
