"""
Tool: score_transaction (Stage 2 - FULL ML SCORING)
Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.
Returns risk band, triggered rules, top-5 SHAP explanations, and dynamic tool guidance.
"""

import pandas as pd
from mcp import types
from fraud_detection.ml_artifacts import THRESHOLD, MODEL, CALIBRATOR
from fraud_detection.config import BAND_LOW, BAND_MEDIUM, BAND_HIGH, MERCHANT_RECURRENCE_THRESHOLD, MERCHANT_RECURRENCE_WINDOW_H
from fraud_detection.feature_engineering import build_feature_vector, shap_top5
from fraud_detection.rules_engine import apply_rules, risk_band, rec_action
from fraud_detection.utils import get_db
from fraud_detection.merchant_tracking import _merchant_flag_count

async def score_transaction(args):
    """
    STAGE 2 — FULL ML SCORING. Always call first for every FLAGGED transaction.
    Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.
    """
    txn = args.get("transaction", {}); db = get_db()
    try:
        feat_df = build_feature_vector(txn, db)   # FIX-1 + FIX-4 + FIX-9
        for col in [c for c in feat_df.columns if c.startswith("f_")]:
            txn[col] = float(feat_df[col].values[0])
        txn.setdefault("risk_score", float(feat_df.get("risk_score", pd.Series([2.5])).values[0]))
        feat_df["risk_score"] = txn["risk_score"]
        ml  = float(MODEL.predict_proba(feat_df)[0, 1])
        cal = float(CALIBRATOR.predict([ml])[0])
        final, fired = apply_rules(cal, txn)
        band = risk_band(final); action = rec_action(band)

        shap_lines = []
        for e in shap_top5(feat_df):
            shap_lines.append(f"  {'[^]' if e['dir']=='toward_fraud' else '[v]'} {e['feature']:<35} val={e['value']:.3f}  shap={e['shap']:+.4f}")

        mfr = float(txn.get('merchantFraudRate',0))
        merchant_id = txn.get('merchant_id','')

        # FIX-6: check recurrence at Stage 2 as well
        recurrence_count = _merchant_flag_count(merchant_id)
        recurrence_note = (
            f"\n  ⚠️  Merchant recurrence: {recurrence_count} CRITICAL flags in {MERCHANT_RECURRENCE_WINDOW_H}h — call get_merchant_risk."
            if recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD else ""
        )

        guidance_parts = []
        if band == 'LOW':
            guidance_parts = [
                "Call get_merchant_onboarding to confirm no known-brand override needed.",
                "Disposition: accept.",
                "Then add_case_note (≤400 chars) + update_case_status(disposition='accept').",
            ]
        elif band == 'MEDIUM':
            guidance_parts = [
                "Call get_customer_profile + get_merchant_onboarding.",
                "If profile fraud_rate > 20% also call get_recent_txns.",
                "Disposition: accept_1fa — NO customer outreach needed, 1FA is the verification.",
                "Then add_case_note (≤400 chars) + update_case_status(disposition='accept_1fa').",
            ]
        elif band == 'HIGH':
            guidance_parts = [
                "Call get_customer_profile + get_recent_txns + get_merchant_onboarding.",
                "If profile fraud_rate > 30% call get_linked_accounts.",
                f"{'Call get_merchant_risk (merchantFraudRate elevated). ' if mfr > 0.05 else ''}",
                "Disposition: accept_and_alert (known brand) or deny (unknown/registered with clear fraud).",
                "Outreach: merchant_only if merchant anomaly is primary; none if transaction-level signal.",
                "End: add_case_note (≤400 chars) + update_case_status.",
            ]
        else:  # CRITICAL
            guidance_parts = [
                "Call get_device_assoc + get_ip_intelligence + get_merchant_onboarding immediately.",
                "Then get_customer_profile + get_recent_txns.",
                # FIX-8: explicit fallback instruction when profile returns no records
                "  ↳ FIX-8: If get_customer_profile returns no records, still call get_recent_txns(card=<card_number>) before verdict.",
                "If device ring signal -> get_linked_accounts.",
                f"{'Call get_merchant_risk. ' if mfr > 0.05 or recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD else ''}",
                "Consider get_similar_fraud_cases if pattern is unusual.",
                "Disposition: deny. KNOWN BRAND RULE: if trust_tier=known_brand cap at accept_and_alert.",
                "Outreach: none for clear fraud rings; customer_only for ambiguous denies.",
                "End: add_case_note (≤400 chars) + update_case_status(disposition='deny').",
            ]

        dc_flag_label = 'no'
        if txn.get('f_datacenter_ip'):
            dc_flag_label = 'YES (CIDR fallback)' if not txn.get('ip_isp') else 'YES (ip_isp match)'

        out = f"""FRAUD SCORING RESULT  [STAGE 2]
================================
Risk score (computed)   : {txn.get('risk_score',0):.2f}
ML probability (raw)    : {ml:.4f}
Calibrated probability  : {cal:.4f}
Final risk score        : {final:.4f}
Risk band               : {band}
Recommended action      : {action}
Datacenter IP flag      : {dc_flag_label}
Frictionless bypass     : {'YES [!] — 3DS silent pass + disposable/new-account' if txn.get('f_frictionless_suspicious') else 'no'}{recurrence_note}

RULES TRIGGERED ({len(fired)})
  {(chr(10)+'  ').join(fired) if fired else 'none'}

TOP-5 SHAP EXPLANATIONS
{chr(10).join(shap_lines)}

DECISION SUMMARY
  Band thresholds : LOW<{BAND_LOW} | MEDIUM<{BAND_MEDIUM} | HIGH<{BAND_HIGH} | CRITICAL≥{BAND_HIGH}
  Model threshold : {THRESHOLD:.3f}
  Model verdict   : {'FRAUD' if ml >= THRESHOLD else 'LEGIT'}

DYNAMIC TOOL GUIDANCE
  {(chr(10)+'  ').join(g for g in guidance_parts if g.strip())}
================================"""
        return [types.TextContent(type="text", text=out)]
    finally: db.close()
