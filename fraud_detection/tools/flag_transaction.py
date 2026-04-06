"""
Tool: flag_transaction (Stage 1 - TRIAGE GATE)
Runs lightweight ML + rule engine with zero DB queries to decide if investigation is warranted.
Returns CLEARED or FLAGGED with suggested tools for Stage 2.
"""

from datetime import datetime
import pandas as pd
import numpy as np
from mcp import types
from fraud_detection.ml_artifacts import MODEL, CALIBRATOR, FEATURE_COLS, CAT_COLS, CAT_ENCODINGS, ROLLING_FEATURES, THRESHOLD
from fraud_detection.config import TRIAGE_THRESHOLD, CASE_NOTE_MAX_CHARS, MERCHANT_RECURRENCE_THRESHOLD, MERCHANT_RECURRENCE_WINDOW_H
from fraud_detection.flags import compute_flags
from fraud_detection.rules_engine import apply_rules, risk_band, rec_action
from fraud_detection.feature_engineering import triage_score
from fraud_detection.merchant_tracking import _record_merchant_flag, _merchant_flag_count

async def flag_transaction(args):
    """
    STAGE 1 — TRIAGE GATE. Call this on every incoming transaction before anything else.
    Runs lightweight ML + rule engine with zero DB queries to decide if investigation is warranted.
    """
    txn = compute_flags(dict(args.get("transaction", {})))   # FIX-1 + FIX-4
    try:    ts = pd.to_datetime(txn.get('purchase_date', datetime.utcnow().isoformat()))
    except: ts = datetime.utcnow()
    row = dict(txn)
    row.update({'hour_of_day':ts.hour,'day_of_week':ts.dayofweek,
                'is_weekend':int(ts.dayofweek>=5),'is_night':int(ts.hour>=22 or ts.hour<=5)})
    row.setdefault('account_age_min_computed', row.get('account_age_minutes',0))
    for vf in ROLLING_FEATURES: row.setdefault(vf, 0)
    row.setdefault('merchant_velocity_5min', 0)  # FIX-9: not available at triage (no DB)
    for col in CAT_COLS: row[f'{col}_enc'] = CAT_ENCODINGS.get(col,{}).get(str(row.get(col,'') or ''),0)
    for col in ['card_number','device_id','emailId','ip','mobileNo']: row.setdefault(f'{col}_freq',1)
    raw = triage_score(row)
    row['risk_score'] = round(raw * 206.0, 4)   # FIX-4: updated denominator
    feat_df = pd.DataFrame([{col: float(row.get(col) or 0) for col in FEATURE_COLS}])
    ml_prob  = float(MODEL.predict_proba(feat_df)[0, 1])
    cal_prob = float(CALIBRATOR.predict([ml_prob])[0])
    score, fired = apply_rules(cal_prob, txn)
    flagged = score >= TRIAGE_THRESHOLD

    # FIX-6: record CRITICAL flag and check merchant recurrence
    merchant_id   = txn.get('merchant_id', '')
    merchant_name = txn.get('merchant_name', '')
    merchant_recurrence_count = 0
    merchant_recurrence_warn  = ''
    if flagged:
        merchant_recurrence_count = _record_merchant_flag(merchant_id)
        if merchant_recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD:
            merchant_recurrence_warn = (
                f"\n⚠️  MERCHANT RECURRENCE ALERT: {merchant_name or merchant_id} has been flagged "
                f"{merchant_recurrence_count}x in the last {MERCHANT_RECURRENCE_WINDOW_H}h. "
                f"Call get_merchant_risk in Stage 2."
            )

    # Datacenter detection source annotation (FIX-1)
    dc_source = ''
    if txn.get('f_datacenter_ip'):
        if txn.get('ip_isp'):
            dc_source = ' (detected via ip_isp)'
        else:
            dc_source = ' (detected via CIDR prefix fallback — ip_isp not provided)'

    # FIX-4: frictionless bypass annotation
    frictionless_warn = ''
    if txn.get('f_frictionless_suspicious'):
        frictionless_warn = '\n  Frictionless bypass: frictionless_success + disposable/new-account detected [!]'

    # FIX-5: build suggested_tools — get_merchant_onboarding always included
    suggested = []
    if flagged:
        suggested.append("score_transaction")
        if txn.get('f_disposable_email') or txn.get('f_new_account_high_value') or txn.get('f_frictionless_suspicious'):
            suggested.append("get_customer_profile")
        if txn.get('f_triple_country_mismatch') or txn.get('f_ip_issuer_mismatch'):
            suggested.append("get_ip_intelligence")
        if float(txn.get('merchantFraudRate',0)) > 0.05 or merchant_recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD:
            suggested.append("get_merchant_risk")
        if txn.get('f_api_channel'):
            suggested.append("get_device_assoc")
        # FIX-5: get_merchant_onboarding always in the chain
        suggested.append("get_merchant_onboarding")
        suggested += ["add_case_note","update_case_status"]

    signals = [k.replace('f_','').replace('_',' ') for k in
               ['f_triple_country_mismatch','f_threeds_failed','f_disposable_email',
                'f_frictionless_suspicious','f_new_account_high_value',
                'f_high_merchant_fraud_rate','f_api_channel','f_high_amount',
                'f_ip_issuer_mismatch','f_datacenter_ip'] if txn.get(k)]

    dc_line = f"\n  Datacenter IP    : YES{dc_source}" if txn.get('f_datacenter_ip') else ""

    out = f"""TRIAGE GATE RESULT  [STAGE 1]
==============================
Outcome              : {'FLAGGED 🚨' if flagged else 'CLEARED ✅'}
Triage score         : {score:.4f}  (threshold = {TRIAGE_THRESHOLD})
ML probability (raw) : {ml_prob:.4f}
Calibrated prob      : {cal_prob:.4f}{dc_line}{frictionless_warn}
{merchant_recurrence_warn}
RULES FIRED ({len(fired)})
  {(chr(10)+'  ').join(fired) if fired else 'none'}

STATIC RISK SIGNALS ({len(signals)})
  {', '.join(signals) if signals else 'none'}

SUGGESTED STAGE 2 TOOLS
  {' → '.join(suggested) if suggested else 'none — case is CLEARED, call update_case_status only'}

NEXT STEP
  {'Proceed to Stage 2. Call score_transaction next.' if flagged else "Auto-close. Call update_case_status(status='auto_cleared'). No other tools needed."}
==============================
NOTE: Velocity/frequency features are 0 at this stage (no DB). Stage 2 score_transaction
recomputes with full DB-backed features and may produce a different final score."""
    return [types.TextContent(type="text", text=out)]
