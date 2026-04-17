"""
server.py — Fraud Detection MCP Server (Modular Edition)
========================================================
Main orchestration point. Manages tool registry, tool dispatch, and server lifecycle.
Imports all individual modules from the fraud_detection package.

ARCHITECTURE:
  This server is built from modularized components in fraud_detection/:
  - config.py: Configuration constants
  - ml_artifacts.py: Model and explainer loading
  - Business logic modules: flags, rules, velocity, feature engineering, etc.
  - tools/: 13 independent tool implementations
  - utils: Shared utilities and database connection

FIXES APPLIED (All Preserved):
FIX-1:  ip_isp datacenter detection — two-layer approach (string match + CIDR prefix fallback)
FIX-2:  add_case_note hard length cap — 400 chars max
FIX-3:  Tool description for add_case_note updated to state the hard limit
FIX-4:  disposable_plus_frictionless rule added to rule engine
FIX-5:  get_merchant_onboarding added to Stage 1 suggested_tools always
FIX-6:  Merchant recurrence escalation — >= 3 CRITICAL flags in 24h triggers get_merchant_risk
FIX-7:  update_case_status now enforces add_case_note prerequisite
FIX-8:  get_recent_txns fallback when get_customer_profile returns no records for CRITICAL
FIX-9:  velocity_per_merchant feature added to rule engine and feature vector
FIX-10: submit_false_positive_feedback validates rule_triggered against known rules
"""

import sys
import io
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="xmlcharrefreplace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="xmlcharrefreplace")

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# Import configuration from fraud_detection package
from fraud_detection.config import DB_CONFIG, TRIAGE_THRESHOLD, CASE_NOTE_MAX_CHARS
from fraud_detection.ml_artifacts import FEATURE_COLS

# Import tool implementations from fraud_detection package
from fraud_detection.tools.flag_transaction import flag_transaction
from fraud_detection.tools.score_transaction import score_transaction
from fraud_detection.tools.get_customer_profile import get_customer_profile
from fraud_detection.tools.get_recent_txns import get_recent_txns
from fraud_detection.tools.get_device_assoc import get_device_assoc
from fraud_detection.tools.get_linked_accounts import get_linked_accounts
from fraud_detection.tools.get_merchant_onboarding import get_merchant_onboarding
from fraud_detection.tools.get_merchant_risk import get_merchant_risk
from fraud_detection.tools.get_ip_intelligence import get_ip_intelligence
from fraud_detection.tools.get_similar_fraud_cases import get_similar_fraud_cases
from fraud_detection.tools.add_case_note import add_case_note
from fraud_detection.tools.update_case_status import update_case_status
from fraud_detection.tools.submit_false_positive_feedback import submit_false_positive_feedback

# ── MCP Server Setup ────────────────────────────────────────────────────────────
app = Server("fraud-detection")

@app.list_tools()
async def list_tools():
    """
    Define all available tools with descriptions, hints, and input schemas.
    Tools are organized in stages: Stage 1 (triage), Stage 2 (core + intelligence + case mgmt).
    """
    return [
        types.Tool(name="flag_transaction", description="""STAGE 1 — TRIAGE GATE. Call this on every incoming transaction before anything else.
Runs lightweight ML + rule engine with zero DB queries to decide if investigation is warranted.

Returns CLEARED or FLAGGED:
  CLEARED → disposition: accept. Call update_case_status(disposition='accept') only.
  FLAGGED → proceed to Stage 2 starting with score_transaction.

Also returns 'suggested_tools' — ordered hint of which Stage 2 tools are relevant based on fired signals.
get_merchant_onboarding is ALWAYS included — call it before every final disposition.

TIP: Pass ip_isp in the transaction payload for best datacenter detection. If ip_isp is absent,
a CIDR prefix fallback covers AWS, GCP, Azure, Tor exits, and major hosting ranges automatically.

FIX-4: disposable_plus_frictionless rule now fires when frictionless_success is combined with
a disposable email or a new account (<60 min). This is a known 3DS bypass pattern.""",
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"}},"required":["transaction"]}),

        types.Tool(name="score_transaction", description="""STAGE 2 — FULL ML SCORING. Always call first for every FLAGGED transaction.
Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.
Returns risk band, triggered rules, top-5 SHAP explanations, and DYNAMIC TOOL GUIDANCE.

ALWAYS call get_merchant_onboarding before final disposition — merchant trust tier can change verdict.

Band guidance (starting point — apply judgment):
  LOW      → disposition: accept. add_case_note + update_case_status only.
  MEDIUM   → get_customer_profile + get_merchant_onboarding. disposition: accept_1fa.
  HIGH     → get_customer_profile + get_recent_txns + get_merchant_onboarding.
             disposition: accept_and_alert or deny based on merchant trust tier.
  CRITICAL → get_device_assoc + get_ip_intelligence + get_merchant_onboarding baseline.
             disposition: deny (unless known brand — see KNOWN BRAND RULE).

FIX-8: If get_customer_profile returns no records for a CRITICAL transaction, fall back to
get_recent_txns on the card number alone before issuing final verdict. Do not skip it.

Always end with add_case_note (3-5 lines, max 400 chars) + update_case_status.""",
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"},"stage_1_context":{"type":"object"}},"required":["transaction"]}),

        types.Tool(name="get_customer_profile", description="""STAGE 2 — Customer risk profile. Call for MEDIUM+ bands.
Returns: transaction history, fraud rate, failure rate, same-amount repeat detection,
linked cards/devices/emails, velocity stats, known scenarios.
If fraud_rate > 30% or unique_cards > 3 -> call get_linked_accounts.
If scenarios include card_testing or api_bot_attack -> call get_device_assoc.

FIX-8: If this tool returns no records on a CRITICAL transaction, do NOT skip to verdict.
Fall back to get_recent_txns(card=<card_number>) to check for any history on the card alone.""",
            inputSchema={"type":"object","properties":{"email":{"type":"string"},"card":{"type":"string"},"device_id":{"type":"string"}}}),

        types.Tool(name="get_recent_txns", description="""STAGE 2 — Recent transaction history on card/device/email.
Call for HIGH+ bands, or when velocity rules fired, or when profile shows elevated fraud rate.
Returns: last N transactions with amounts, merchants, timestamps, fraud labels, risk scores.
Watch for: excess failure rate, repeat same-amount transactions, rapid IP change across transactions.

FIX-8: Also call with card= when get_customer_profile returns no records on a CRITICAL case.
This ensures first-seen identifiers don't short-circuit the investigation.""",
            inputSchema={"type":"object","properties":{"card":{"type":"string"},"device_id":{"type":"string"},"email":{"type":"string"},"limit":{"type":"integer"},"hours":{"type":"integer"}}}),

        types.Tool(name="get_device_assoc", description="""STAGE 2 — Device association report.
Call for CRITICAL band, API channel, or when profile/recent_txns suggest multi-card usage.
Returns: all cards and emails linked to this device, fraud rates, ring signal.
If unique_cards >= 5 -> call get_linked_accounts. If ring signal = YES -> call get_ip_intelligence.""",
            inputSchema={"type":"object","properties":{"device_id":{"description":"Device ID","type":"string"},"hours":{"description":"Lookback hours (default 168)","type":"integer"}}}),

        types.Tool(name="get_linked_accounts", description="""STAGE 2 — Cross-identifier fraud ring detection.
Finds accounts sharing any identifier: same IP, device_id, email domain (non-generic), card BIN prefix.
Returns: linked accounts, shared identifier type, fraud rates, ring_score.
Call when: device_assoc unique_cards >= 3, profile fraud_rate > 30%, or triple_country_mismatch + HIGH+.""",
            inputSchema={"type":"object","properties":{"card":{"type":"string"},"device_id":{"type":"string"},"email":{"type":"string"},"hours":{"description":"Lookback hours (default 720)","type":"integer"},"ip":{"type":"string"}}}),

        types.Tool(name="get_merchant_onboarding", description="""STAGE 2 — Merchant onboarding context. ALWAYS call before final disposition.
Returns: merchant type, onboarding date, website URL, MCC code, known_brand flag, trust_tier.

Trust tiers and effect on disposition:
  known_brand  -> direct deny BLOCKED (max: accept_and_alert) unless CRITICAL + confirmed ring.
                  Examples: Tanishq, Amazon, Flipkart, Tata, HDFC, Airtel.
  registered   -> standard disposition logic applies.
  unknown      -> treat as elevated risk; leans toward deny for HIGH+.

merchant_type contextualises anomaly:
  jewellery / electronics / travel -> high-value transactions are normal.
  generic_ecomm / unknown          -> high-value warrants more scrutiny.

FIX-5: This tool is now included in Stage 1 suggested_tools for every FLAGGED transaction.""",
            inputSchema={"type":"object","properties":{
                "merchant_id":      {"type":"string"},
                "merchant_name":    {"type":"string"},
                "merchant_country": {"type":"string"},
                "mcc_code":         {"type":"string"}}}),

        types.Tool(name="get_merchant_risk", description="""STAGE 2 — Merchant fraud intelligence and MCC peer comparison.
Returns: historical fraud rate, last 30-day fraud rate, failure rate vs MCC average,
avg transaction amount vs MCC average, velocity vs MCC average, watchlist status.
Call when: merchantFraudRate > 0.05, merchant_country != issuer_country, or HIGH/CRITICAL band.
Watchlisted merchant -> escalate regardless of other signals.

FIX-6: Also auto-triggered when the same merchant_id accumulates >= 3 CRITICAL-band flagged
transactions within 24 hours. This recurrence warning appears in flag_transaction output.""",
            inputSchema={"type":"object","properties":{"merchantFraudRate":{"type":"number"},"merchant_category":{"type":"string"},"merchant_country":{"type":"string"},"merchant_id":{"type":"string"}}}),

        types.Tool(name="get_ip_intelligence", description="""STAGE 2 — IP reputation and geolocation intelligence.
Returns: VPN/proxy/datacenter detection, country mismatch, historical fraud from this IP and /24 subnet.
Call when: ip_country != issuer_country, authenticationType = not_attempted, CRITICAL band,
or device_assoc returns fraud ring signal = YES.

NOTE: f_datacenter_ip uses a two-layer check (isp string + CIDR prefix fallback),
so datacenter detection works even when ip_isp is not passed in the transaction payload.""",
            inputSchema={"type":"object","properties":{"ip":{"type":"string"},"ip_country_long":{"type":"string"},"issuerCountryCode":{"type":"string"}}}),

        types.Tool(name="get_similar_fraud_cases", description="""STAGE 2 — Top-N most similar confirmed fraud cases from history.
Matches on binary flags, auth type, device channel, IP country, amount range.
Call when: unusual signal combination, grey zone MEDIUM band, need historical precedent,
or checking if this matches a known ongoing fraud campaign.""",
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"},"top_n":{"type":"integer"},"fraud_only":{"type":"boolean"},"scenario_filter":{"type":"string"}}}),

        types.Tool(name="add_case_note", description="""STAGE 2 — Append structured case report. MANDATORY before update_case_status.
HARD LIMIT: content must be 400 characters or fewer. Submissions over 400 chars are REJECTED.

Report template (3-5 lines, ≤400 chars total):
  Line 1: Anomaly detected — which rule fired and why.
  Line 2: Other anomalies checked (excess failures, same-amount repeats, multi-card, IP change).
  Line 3: Merchant context — type, trust tier, behaviour vs MCC.
  Line 4: Alert category verdict with confidence.
  Line 5 (optional): Recommended next action and outreach target if not already clear.

Write 3 tight lines for simple cases, up to 5 for complex ones. Do NOT write prose paragraphs.""",
            inputSchema={"type":"object","properties":{
                "transaction_id":  {"type":"string"},
                "note_type":       {"type":"string","enum":["initial_assessment","tool_finding","hypothesis_change","final_verdict","escalation_note"]},
                "content":         {"type":"string","description":"3-5 lines, MAX 400 characters. Submissions over 400 chars are rejected."},
                "risk_band":       {"type":"string"},
                "alert_category":  {"type":"string","enum":["false_alert","genuine","need_merchant_outreach","need_customer_outreach","need_both_outreach"]},
                "confidence":      {"type":"number"}},
                "required":["transaction_id","note_type","content","alert_category"]}),

        types.Tool(name="update_case_status", description="""STAGE 2 — Set final disposition. ALWAYS call last. report field is MANDATORY.
add_case_note MUST be called before this tool — cases without a note will be rejected.

Disposition values:
  accept           — Low risk, approve directly, no outreach.
  accept_1fa       — Approve after OTP/biometric. NO customer outreach — 1FA is the verification.
  accept_and_alert — Accept but flag for monitoring. Merchant outreach only if merchant anomaly
                     is the PRIMARY signal, not just elevated rate.
  deny             — Block. KNOWN BRAND RULE: cannot deny known-brand merchant unless CRITICAL
                     band + confirmed fraud ring.

outreach_target (set for deny and accept_and_alert only):
  none             — Clear fraud, block and escalate, no outreach.
  customer_only    — Ambiguous deny, customer should verify.
  merchant_only    — Merchant behaviour is primary anomaly.
  both             — Both contexts needed.

FIX-7: Server enforces that add_case_note has been called for this transaction_id before
accepting this call. Missing note returns an error.""",
            inputSchema={"type":"object","properties":{
                "transaction_id":    {"type":"string"},
                "disposition":       {"type":"string","enum":["accept","accept_1fa","accept_and_alert","deny"]},
                "risk_band":         {"type":"string"},
                "final_score":       {"type":"number"},
                "alert_category":    {"type":"string","enum":["false_alert","genuine","need_merchant_outreach","need_customer_outreach","need_both_outreach"]},
                "outreach_required": {"type":"string","enum":["no","conditional","yes"]},
                "outreach_target":   {"type":"string","enum":["none","customer_only","merchant_only","both"]},
                "report":            {"type":"string","description":"MANDATORY 3-5 line rationale"},
                "recommended_action":{"type":"string"},
                "tools_used":        {"type":"array","items":{"type":"string"}}},
                "required":["transaction_id","disposition","report"]}),

        types.Tool(name="submit_false_positive_feedback", description="""STAGE 2 — Flag a deny as a false positive and feed back to rule engine.
Call when a deny verdict is uncertain and correct disposition should have been accept_and_alert
or accept_1fa. Logs transaction features and over-triggered rule for human analyst review.
Effect: analysts can update rule weights or add merchant exceptions based on feedback.

FIX-10: rule_triggered must be one of the known rule names. Invalid names are rejected with
a list of valid options so the feedback loop stays clean and queryable.""",
            inputSchema={"type":"object","properties":{
                "transaction_id":       {"type":"string"},
                "original_disposition": {"type":"string","enum":["deny"]},
                "correct_disposition":  {"type":"string","enum":["accept","accept_1fa","accept_and_alert"]},
                "rule_triggered":       {"type":"string","description":"Must match a known rule name exactly (see server KNOWN_RULE_NAMES)"},
                "analyst_note":         {"type":"string","description":"Why this is a false positive"}},
                "required":["transaction_id","original_disposition","correct_disposition","rule_triggered"]}),
    ]

@app.call_tool()
async def call_tool(name, arguments):
    """Route tool calls to their implementations. Catches and logs errors."""
    try:
        handlers = {
            "flag_transaction": flag_transaction,
            "score_transaction": score_transaction,
            "get_customer_profile": get_customer_profile,
            "get_recent_txns": get_recent_txns,
            "get_device_assoc": get_device_assoc,
            "get_linked_accounts": get_linked_accounts,
            "get_merchant_onboarding": get_merchant_onboarding,
            "get_merchant_risk": get_merchant_risk,
            "get_ip_intelligence": get_ip_intelligence,
            "get_similar_fraud_cases": get_similar_fraud_cases,
            "add_case_note": add_case_note,
            "update_case_status": update_case_status,
            "submit_false_positive_feedback": submit_false_positive_feedback,
        }
        if name in handlers:
            return await handlers[name](arguments)
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error in {name}: {str(e)}")]

# ── Entry point ──────────────────────────────────────────────────────────────
async def main():
    """Start MCP server in stdio mode. Prints startup diagnostics to stderr."""
    print("Fraud Detection MCP Server  [Modular Edition]", file=sys.stderr)
    print(f"  Stage 1 : flag_transaction  (triage threshold={TRIAGE_THRESHOLD})", file=sys.stderr)
    print(f"  Stage 2 : score_transaction -> [LLM decides] -> add_case_note + update_case_status", file=sys.stderr)
    print(f"  Tools   : 13 total (1 triage | 4 core | 5 intelligence | 2 case mgmt | 1 feedback)", file=sys.stderr)
    print(f"  Dispositions: accept | accept_1fa | accept_and_alert | deny", file=sys.stderr)
    print(f"  Features: {len(FEATURE_COLS)}  |  DB: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}", file=sys.stderr)
    print(f"  FIX-1 : Datacenter detection — ip_isp match + CIDR prefix fallback", file=sys.stderr)
    print(f"  FIX-2 : Case note hard cap — {CASE_NOTE_MAX_CHARS} chars max", file=sys.stderr)
    print(f"  FIX-3 : Tool description updated with hard cap notice", file=sys.stderr)
    print(f"  FIX-4 : disposable_plus_frictionless rule — 3DS bypass detection", file=sys.stderr)
    print(f"  FIX-5 : get_merchant_onboarding always in Stage 1 suggested_tools", file=sys.stderr)
    print(f"  FIX-6 : Merchant recurrence alert for >= 3 CRITICAL flags in 24h", file=sys.stderr)
    print(f"  FIX-7 : update_case_status enforces add_case_note prerequisite", file=sys.stderr)
    print(f"  FIX-8 : get_customer_profile no-records fallback to get_recent_txns for CRITICAL", file=sys.stderr)
    print(f"  FIX-9 : merchant_velocity_5min feature + api_merchant_velocity rule", file=sys.stderr)
    print(f"  FIX-10: submit_false_positive_feedback validates rule_triggered against KNOWN_RULE_NAMES", file=sys.stderr)
    print(f"  This server imports from modularized fraud_detection package.", file=sys.stderr)
    print("Ready.\n", file=sys.stderr)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
