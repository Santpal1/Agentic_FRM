"""
Tool: score_transaction (Stage 2 - FULL ML SCORING)
Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.
Returns risk band, triggered rules, top-5 SHAP explanations, and dynamic tool guidance.

Enhanced to:
- Accept Stage 1 context to avoid re-computation
- Use centralized tool router for consistent recommendations
- Map SHAP features to investigative tools
- Provide explicit case closing checklist
- Early exit for LOW/CLEARED risk
"""

import json
import pandas as pd
from mcp import types
from fraud_detection.ml_artifacts import THRESHOLD, MODEL, CALIBRATOR
from fraud_detection.config import BAND_LOW, BAND_MEDIUM, BAND_HIGH, BAND_CLEARED, MERCHANT_RECURRENCE_THRESHOLD, MERCHANT_RECURRENCE_WINDOW_H
from fraud_detection.feature_engineering import build_feature_vector, shap_top5
from fraud_detection.rules_engine import apply_rules, risk_band, rec_action
from fraud_detection.utils import get_db
from fraud_detection.merchant_tracking import get_merchant_flag_count, record_merchant_flag
from fraud_detection.tool_router import get_tools_for_band, get_tools_for_shap_features, dedupe_and_prioritize, BAND_TOOL_MAPPING

async def score_transaction(args):
    """
    STAGE 2 — FULL ML SCORING. Always call first for every FLAGGED transaction.
    Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.
    
    ENHANCEMENT: Accepts optional stage_1_context to avoid re-computation of flags/rules.
    """
    txn = args.get("transaction", {})
    stage_1_context = args.get("stage_1_context", {})  # NEW: Accept Stage 1 context
    
    # NEW: Early exit optimization for CLEARED/LOW risk
    if stage_1_context.get('status') == 'CLEARED':
        return [types.TextContent(type="text", text=f"""AUTOMATED EARLY EXIT [STAGE 2]
===================================
Status              : CLEARED (no risk signals detected)
Triage score        : {stage_1_context.get('triage_score', 0):.4f}
Recommendation      : Approve directly

NEXT STEP
  Call update_case_status(disposition='accept', report='<brief reason>')
===================================""")]
    
    db = get_db()
    try:
        feat_df = build_feature_vector(txn, db)   # FIX-1 + FIX-4 + FIX-9
        
        # NEW: Skip flag re-computation if Stage 1 provided flags (optimization)
        if stage_1_context.get('flags_fired'):
            for flag in stage_1_context['flags_fired']:
                txn[flag] = 1
        
        for col in [c for c in feat_df.columns if c.startswith("f_")]:
            txn[col] = float(feat_df[col].values[0])
        txn.setdefault("risk_score", float(feat_df.get("risk_score", pd.Series([2.5])).values[0]))
        feat_df["risk_score"] = txn["risk_score"]
        ml  = float(MODEL.predict_proba(feat_df)[0, 1])
        cal = float(CALIBRATOR.predict([ml])[0])
        
        # ENHANCED: Combine Stage 1 results with Stage 2 recalculation
        # Stage 2 has real velocity features, so rules may fire differently
        # Always recompute rules to capture velocity-based signals
        final, fired_stage2 = apply_rules(cal, txn)
        
        # Log Stage 1 rules for context, but use Stage 2 rules for final decision
        stage1_rules = stage_1_context.get('rules_fired', []) if stage_1_context else []
        fired = fired_stage2  # Stage 2 rules take precedence
        
        band = risk_band(final); action = rec_action(band)

        # ENHANCED SHAP ANALYSIS with tool mapping
        shap_features = shap_top5(feat_df)
        shap_lines = []
        for e in shap_features:
            shap_lines.append(f"  {'[^]' if e['dir']=='toward_fraud' else '[v]'} {e['feature']:<35} val={e['value']:.3f}  shap={e['shap']:+.4f}")
        
        # NEW: Map SHAP features to investigative tools
        shap_tool_recommendations = get_tools_for_shap_features(shap_features)

        mfr = float(txn.get('merchantFraudRate',0))
        merchant_id = txn.get('merchant_id','')

        # FIX-6: check recurrence at Stage 2 as well (now DB-backed)
        recurrence_count = get_merchant_flag_count(merchant_id)
        recurrence_note = (
            f"\n  ⚠️  Merchant recurrence: {recurrence_count} CRITICAL flags in {MERCHANT_RECURRENCE_WINDOW_H}h — call get_merchant_risk."
            if recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD else ""
        )

        # NEW: Centralized tool routing (replaces hardcoded guidance_parts)
        has_ring_signal = txn.get('device_cards_24h', 0) >= 5 or txn.get('email_cards_total', 0) >= 5
        routed_tools = get_tools_for_band(band, mfr, has_ring_signal)
        
        # Deduplicate tools from SHAP recommendations and band routing
        all_tools = routed_tools + shap_tool_recommendations
        final_tools = dedupe_and_prioritize(all_tools)
        
        # NEW: Explicit case closing checklist (helps LLM understand workflow)
        case_checklist = """CASE CLOSING CHECKLIST (Required steps in order)
  [1] add_case_note (≤400 chars) — Document investigation findings and reasoning
  [2] update_case_status(disposition='...' report='...') — MANDATORY fields
      - disposition: accept | accept_1fa | accept_and_alert | deny
      - report: 3-5 line executive summary (required)
  [3] Case automatically persisted to DB after Step 2"""

        # NEW: Velocity signals dashboard
        velocity_dashboard = f"""VELOCITY SIGNALS (Real-time features from DB)
  5-min burst       : {feat_df.get('velocity_5min_count', pd.Series([0])).values[0]:.0f} txns
  1-hr accumulation : {feat_df.get('velocity_1hr_count', pd.Series([0])).values[0]:.0f} txns
  24-hr accumulation: {feat_df.get('velocity_24hr_count', pd.Series([0])).values[0]:.0f} txns
  Device cards (24h): {feat_df.get('device_cards_24h', pd.Series([0])).values[0]:.0f} unique cards
  Email cards (all) : {feat_df.get('email_cards_total', pd.Series([0])).values[0]:.0f} unique cards
  Merchant velocity : {feat_df.get('merchant_velocity_5min', pd.Series([0])).values[0]:.0f} txns at this merchant"""

        # NEW: Structured tool routing output for LLM
        tools_text_blocks = []
        current_priority = None
        for tool_spec in final_tools:
            priority_level = tool_spec.get('priority_level', tool_spec.get('priority'))
            if priority_level != current_priority:
                current_priority = priority_level
                tools_text_blocks.append(f"\n[{priority_level}]")
            reason = tool_spec.get('reason', '')
            tools_text_blocks.append(f"  → {tool_spec['tool']}: {reason}")
        
        tools_section = "STRUCTURED TOOL ROUTING (Prioritized investigation chain)\n" + "".join(tools_text_blocks)

        dc_flag_label = 'no'
        if txn.get('f_datacenter_ip'):
            dc_flag_label = 'YES (CIDR fallback)' if not txn.get('ip_isp') else 'YES (ip_isp match)'

        # NEW: Comprehensive output with all enhancements
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

TOP-5 SHAP EXPLANATIONS (Feature impact on fraud score)
{chr(10).join(shap_lines)}

SHAP-TO-TOOLS MAPPING (What to investigate based on top features)
{''.join([f"  {st['tool']}: {st['reason']}" + chr(10) for st in shap_tool_recommendations]) if shap_tool_recommendations else '  none — all features normal'}

{velocity_dashboard}

{tools_section}

DECISION SUMMARY
  Band thresholds : CLEARED<{BAND_CLEARED} | LOW<{BAND_LOW} | MEDIUM<{BAND_MEDIUM} | HIGH<{BAND_HIGH} | CRITICAL≥{BAND_HIGH}
  Model threshold : {THRESHOLD:.3f}
  Model verdict   : {'FRAUD' if ml >= THRESHOLD else 'LEGIT'}

{case_checklist}

[STRUCTURED ROUTING JSON]
{json.dumps({
    'band': band,
    'final_score': round(final, 4),
    'disposition_recommendation': BAND_TOOL_MAPPING[band].get('disposition', 'review_manually'),
    'outreach_required': BAND_TOOL_MAPPING[band].get('outreach_required', 'conditional'),
    'tools_ordered': [t['tool'] for t in final_tools],
    'tools_detailed': final_tools
}, indent=2, default=str)}
================================"""
        return [types.TextContent(type="text", text=out)]
    finally: db.close()
