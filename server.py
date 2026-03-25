"""
server.py — Fraud Detection MCP Server  (Workflow A · Dynamic Tool Edition)
============================================================================

ARCHITECTURE — WORKFLOW A WITH DYNAMIC TOOL SELECTION
------------------------------------------------------
The pipeline has two stages. The LLM decides dynamically which Stage 2
tools to call and in what order, guided by what each tool returns.

  STAGE 1 — TRIAGE GATE
  ──────────────────────
  flag_transaction
    Every raw transaction hits this first. Lightweight ML + rule engine,
    zero DB calls. Returns CLEARED (stop) or FLAGGED (proceed to Stage 2)
    along with a hint about which signals fired so the LLM can plan ahead.

  STAGE 2 — DYNAMIC AGENTIC INVESTIGATION
  ─────────────────────────────────────────
  The LLM receives the FLAGGED result and decides which tools to call,
  in what order, and whether intermediate results warrant calling more tools.

  Tool menu (LLM chooses):

    score_transaction        Full ML score + SHAP. Always call first in Stage 2.
                             Result's risk band guides how deep to investigate:
                               LOW      → close, no further tools needed
                               MEDIUM   → call get_customer_profile at minimum
                               HIGH     → call profile + recent txns
                               CRITICAL → call all tools including device assoc
                                          + consider get_linked_accounts +
                                          get_merchant_risk + get_ip_intelligence

    get_customer_profile     Account history, fraud rate, linkage signals.
    get_recent_txns          Velocity and recent transaction history.
    get_device_assoc         All cards/emails linked to this device (7-day window).
    get_linked_accounts      NEW — Cross-identifier ring detection (IP/device/BIN/domain).
    get_merchant_risk        NEW — Merchant fraud rate, chargebacks, peer comparison.
    get_ip_intelligence      NEW — VPN/proxy detection, geolocation, subnet fraud history.
    get_similar_fraud_cases  NEW — Top-N most similar confirmed fraud cases by feature similarity.
    add_case_note            NEW — Append structured note to case record for audit trail.
    update_case_status       NEW — Set final case status and close the investigation.

TOOL DECISION GUIDANCE FOR THE LLM
────────────────────────────────────
After score_transaction, use this as a starting point but apply judgment:

  LOW band       → close immediately, call add_case_note + update_case_status only
  MEDIUM band    → get_customer_profile → re-evaluate → add_case_note + update_case_status
  HIGH band      → get_customer_profile + get_recent_txns → if fraud_rate > 30%
                   also get_linked_accounts → add_case_note + update_case_status
  CRITICAL band  → all tools as warranted → add_case_note + update_case_status
                   always includes get_device_assoc + get_ip_intelligence

  Additional triggers (call regardless of band):
    merchantFraudRate > 0.05          → get_merchant_risk
    ip_country != issuer_country      → get_ip_intelligence
    profile shows 3+ linked cards     → get_linked_accounts
    unusual signal combo              → get_similar_fraud_cases

REQUIRED DB TABLES (run once):
    CREATE TABLE IF NOT EXISTS case_notes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        transaction_id VARCHAR(64) NOT NULL,
        note_type VARCHAR(32) NOT NULL,
        content TEXT NOT NULL,
        risk_band VARCHAR(16),
        confidence FLOAT,
        created_at DATETIME NOT NULL,
        INDEX idx_txn (transaction_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS case_status (
        transaction_id VARCHAR(64) PRIMARY KEY,
        status VARCHAR(32) NOT NULL,
        risk_band VARCHAR(16),
        final_score FLOAT,
        recommended_action VARCHAR(128),
        tools_used JSON,
        updated_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

Usage:
    pip install mcp mysql-connector-python pandas numpy scikit-learn shap

Claude Desktop config (~/.config/claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "fraud-detection": {
          "command": "python",
          "args": ["/absolute/path/to/fraud_mcp/server.py"]
        }
      }
    }
"""

import sys
import io
import json
import pickle
import os
from datetime import datetime, timedelta

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
import mysql.connector
from sklearn.isotonic import IsotonicRegression
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_CONFIG = {
    'host':     'localhost',
    'port':     3306,
    'user':     'root',
    'password': '',
    'database': 'fraud_detection',
    'charset':  'utf8mb4',
}

TRIAGE_THRESHOLD = 0.25   # Stage 1 gate — below = auto-cleared
BAND_LOW    = 0.30
BAND_MEDIUM = 0.60
BAND_HIGH   = 0.80        # above = CRITICAL

# ── Load ML artifacts ──────────────────────────────────────────────────────────
print("Loading ML artifacts...", file=sys.stderr)

with open(os.path.join(BASE_DIR, 'model.pkl'), 'rb') as f:
    MODEL = pickle.load(f)
with open(os.path.join(BASE_DIR, 'shap_explainer.pkl'), 'rb') as f:
    EXPLAINER = pickle.load(f)
with open(os.path.join(BASE_DIR, 'feature_columns.json'), 'r') as f:
    FEAT_META = json.load(f)
with open(os.path.join(BASE_DIR, 'cat_encodings.json'), 'r') as f:
    CAT_ENCODINGS = json.load(f)

FEATURE_COLS     = FEAT_META['feature_cols']
CAT_COLS         = FEAT_META['cat_features']
ROLLING_FEATURES = FEAT_META['rolling_features']
THRESHOLD        = 0.650   # GAP-02 FIX: overrides feature_columns.json value of 0.830

print(f"  Model loaded : {len(FEATURE_COLS)} features, threshold={THRESHOLD:.3f}", file=sys.stderr)

# ── Isotonic calibration ───────────────────────────────────────────────────────
_cal_scores = np.array([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
_cal_probs  = np.array([0.02, 0.05, 0.10, 0.18, 0.28, 0.40, 0.54, 0.68, 0.80, 0.89, 0.94])
CALIBRATOR  = IsotonicRegression(out_of_bounds='clip')
CALIBRATOR.fit(_cal_scores, _cal_probs)
print("  Calibrator ready", file=sys.stderr)

# ── Rule engine ────────────────────────────────────────────────────────────────
RULES = [
    ('velocity_burst_5min',          lambda t: t.get('velocity_5min_count', 0) >= 3,                                                                                                   +0.15),
    ('multi_card_device',            lambda t: t.get('device_cards_24h', 0) >= 3,                                                                                                      +0.12),
    ('high_email_card_count',        lambda t: t.get('email_cards_total', 0) >= 10,                                                                                                    +0.10),
    ('triple_country_mismatch',      lambda t: t.get('f_triple_country_mismatch', 0) == 1,                                                                                             +0.08),
    ('disposable_plus_3ds_fail',     lambda t: t.get('f_disposable_email', 0) == 1 and t.get('f_threeds_failed', 0) == 1,                                                              +0.12),
    ('api_plus_datacenter',          lambda t: t.get('f_api_channel', 0) == 1 and t.get('f_datacenter_ip', 0) == 1,                                                                    +0.10),
    ('new_acct_high_value',          lambda t: t.get('f_new_account_high_value', 0) == 1,                                                                                              +0.08),
    ('api_channel_no_page',          lambda t: str(t.get('deviceChannel','')).upper()=='API' and int(t.get('merchantPageTxn',1))==0,                                                   +0.10),
    ('api_channel_new_acct',         lambda t: str(t.get('deviceChannel','')).upper()=='API' and float(t.get('account_age_minutes',9999))<60,                                          +0.15),
    ('api_foreign_ip_no_auth',       lambda t: str(t.get('deviceChannel','')).upper()=='API' and str(t.get('ip_country_long','India'))!='India' and str(t.get('authenticationType',''))=='not_attempted', +0.12),
    ('late_night_high_value',        lambda t: _hour(t.get('purchase_date',''))<5 and float(t.get('amount_inr',0) or t.get('purchase_amount',0))>20000,                                +0.06),
    ('micro_account_critical_value', lambda t: float(t.get('account_age_minutes',9999))<10 and float(t.get('amount_inr',0) or t.get('purchase_amount',0))>50000,                       +0.25),
    ('attempted_auth_failed',        lambda t: str(t.get('authenticationType',''))=='attempted_not_authenticated' and float(t.get('amount_inr',0) or t.get('purchase_amount',0))>10000,+0.05),
    ('foreign_ip_no_auth',           lambda t: str(t.get('ip_country_long','India'))!='India' and str(t.get('issuerCountryCode',''))=='IND' and str(t.get('authenticationType',''))=='not_attempted', +0.10),
    ('email_multi_card',             lambda t: int(t.get('email_cards_total',0))>=2,                                                                                                   +0.08),
    ('long_standing_account',        lambda t: float(t.get('account_age_minutes',0))>=43200,                                                                                           -0.05),
    ('successful_3ds_challenge',     lambda t: str(t.get('authenticationType',''))=='challenge_success',                                                                               -0.04),
    ('low_merchant_fraud_rate',      lambda t: float(t.get('merchantFraudRate',1.0))<0.02,                                                                                             -0.03),
]

def _hour(s):
    try:    return pd.to_datetime(s).hour
    except: return 12

def apply_rules(cal_prob, txn):
    adj, fired = 0.0, []
    for name, cond, delta in RULES:
        try:
            if cond(txn): adj += delta; fired.append(f"{name} ({delta:+.2f})")
        except: pass
    return float(np.clip(cal_prob + adj, 0.0, 1.0)), fired

def risk_band(s):
    if s < BAND_LOW:    return 'LOW'
    if s < BAND_MEDIUM: return 'MEDIUM'
    if s < BAND_HIGH:   return 'HIGH'
    return 'CRITICAL'

def rec_action(band):
    return {'LOW':'auto_close — no further action required',
            'MEDIUM':'step_up_auth — trigger OTP or biometric challenge',
            'HIGH':'open_case — escalate to analyst review',
            'CRITICAL':'block_transaction — immediate block + open post-block review case'}[band]

# ── Feature helpers ────────────────────────────────────────────────────────────
DISPOSABLE = ['tempmail','throwaway','guerrilla','mailinator','yopmail','trashmail',
              'mailnull','tempinbox','throwam','sharklasers','guerrillamailblock',
              'grr.la','guerrillamail.info','guerrillamail.biz','guerrillamail.de',
              'guerrillamail.net','guerrillamail.org','dispostable','fakeinbox',
              'tempail','tempr.email','temp-mail','spamgourmet','mailnesia','maildrop',
              'discard.email','spamherelots','trashmail.at','trashmail.me',
              'trashmail.net','trashmail.org','throwam.com','spamfree24','getairmail',
              'filzmail','kurzepost','objectmail','proxymail','rcpt.at','trash-mail',
              'wegwerfmail','spamgob','tempemail','tmpmail','emailondeck','spambox',
              'mohmal','mytemp','tempsky','inboxbear','temp-inbox']
DATACENTER = ['aws','google cloud','azure','digitalocean','linode','vultr','ovh','hetzner']


def compute_flags(row):
    """Compute all f_ binary flags from raw transaction fields. Pure Python, no DB."""
    amt   = float(row.get('amount_inr') or row.get('purchase_amount') or 0)
    isc   = str(row.get('issuerCountryCode') or '')
    ipc   = str(row.get('ip_country_long') or '')
    mc    = str(row.get('merchant_country') or '')
    auth  = str(row.get('authenticationType') or '')
    email = str(row.get('emailId') or row.get('email') or '')
    isp   = str(row.get('ip_isp') or '').lower()
    dch   = str(row.get('deviceChannel') or '')
    page  = int(row.get('merchantPageTxn') or 1)
    mfr   = float(row.get('merchantFraudRate') or 0)
    age   = float(row.get('account_age_minutes') or 0)
    row['f_high_amount']              = int(amt > 50000)
    row['f_ip_issuer_mismatch']       = int(ipc != 'India' and isc == 'IND')
    row['f_triple_country_mismatch']  = int(isc == 'IND' and mc != 'IND' and ipc != 'India')
    row['f_high_merchant_fraud_rate'] = int(mfr > 0.08)
    row['f_new_account_high_value']   = int(age < 60 and amt > 10000)
    row['f_threeds_failed']           = int(auth in ['challenge_failed','not_attempted'])
    row['f_disposable_email']         = int(any(d in email for d in DISPOSABLE))
    row['f_datacenter_ip']            = int(any(k in isp for k in DATACENTER))
    row['f_api_channel']              = int(dch == 'API')
    row['f_bin_country_mismatch']     = int(isc == 'IND' and mc != 'IND')
    row['f_merchant_page_redirect']   = int(page == 0)
    return row


def triage_score(txn):
    """Normalised [0,1] static risk score. No DB. Used in Stage 1."""
    w = {'f_high_amount':18,'f_ip_issuer_mismatch':22,'f_triple_country_mismatch':24,
         'f_high_merchant_fraud_rate':18,'f_new_account_high_value':28,'f_threeds_failed':32,
         'f_disposable_email':14,'f_datacenter_ip':18,'f_api_channel':9,
         'f_bin_country_mismatch':18,'f_merchant_page_redirect':8}
    return float(np.clip(sum(float(txn.get(k,0))*v for k,v in w.items())/190.0, 0.0, 1.0))


def build_feature_vector(txn, db_conn):
    """Full DB-backed feature vector for Stage 2 ML scoring."""
    row = dict(txn)
    try:    ts = pd.to_datetime(row.get('purchase_date', datetime.utcnow().isoformat()))
    except: ts = datetime.utcnow()
    row.update({'hour_of_day':ts.hour,'day_of_week':ts.dayofweek,
                'is_weekend':int(ts.dayofweek>=5),'is_night':int(ts.hour>=22 or ts.hour<=5)})
    row.setdefault('account_age_min_computed', row.get('account_age_minutes',0))
    if any(row.get(f) is None for f in ROLLING_FEATURES):
        row = velocity_from_db(row, ts, db_conn)
    cur = db_conn.cursor(dictionary=True)
    for col, db_col in [('card_number','card_number'),('device_id','device_id'),
                         ('emailId','email'),('ip','ip'),('mobileNo','mobile_no')]:
        val = row.get(col) or row.get(db_col)
        try:
            cur.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE {db_col}=%s",(val,))
            r = cur.fetchone(); row[f'{col}_freq'] = int(r['cnt']) if r else 1
        except: row[f'{col}_freq'] = 1
    cur.close()
    for col in CAT_COLS:
        row[f'{col}_enc'] = CAT_ENCODINGS.get(col,{}).get(str(row.get(col,'') or ''),0)
    row = compute_flags(row)
    if not row.get('risk_score'):
        w = {'velocity_5min_count':8,'velocity_1hr_count':3,'device_cards_24h':10,
             'email_cards_total':6,'card_txn_24h':4,'f_high_amount':18,
             'f_ip_issuer_mismatch':22,'f_triple_country_mismatch':24,
             'f_high_merchant_fraud_rate':18,'f_new_account_high_value':28,
             'f_threeds_failed':32,'f_disposable_email':14,'f_datacenter_ip':18,
             'f_api_channel':9,'f_bin_country_mismatch':18,'f_merchant_page_redirect':8}
        base  = sum(float(row.get(k,0) or 0)*v for k,v in w.items())
        noise = float(np.random.normal(0, max(3.0, base*0.08)))
        row['risk_score'] = round(max(0.1, base+noise+2.5), 4)
    return pd.DataFrame([{col: float(row.get(col) or 0) for col in FEATURE_COLS}])


def velocity_from_db(row, ts, db_conn):
    cur = db_conn.cursor(dictionary=True)
    dev = row.get('device_id',''); email = row.get('emailId') or row.get('email','')
    card = row.get('card_number',''); ts_s = ts.strftime('%Y-%m-%d %H:%M:%S')
    try:
        for label, delta in [('velocity_5min_count',timedelta(minutes=5)),
                              ('velocity_1hr_count',timedelta(hours=1)),
                              ('velocity_24hr_count',timedelta(hours=24))]:
            cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE device_id=%s AND purchase_date>=%s AND purchase_date<%s",
                        (dev,(ts-delta).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
            row[label] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT card_number) as cnt FROM transactions WHERE device_id=%s AND purchase_date>=%s AND purchase_date<%s",
                    (dev,(ts-timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
        row['device_cards_24h'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT card_number) as cnt FROM transactions WHERE email=%s",(email,))
        row['email_cards_total'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE email=%s",(email,))
        row['email_txn_count'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE card_number=%s AND purchase_date>=%s AND purchase_date<%s",
                    (card,(ts-timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
        row['card_txn_24h'] = cur.fetchone()['cnt']
    finally: cur.close()
    return row


def shap_top5(feat_df):
    sv = EXPLAINER.shap_values(feat_df)
    df = pd.DataFrame({'feature':FEATURE_COLS,'value':feat_df.values[0],'shap':sv[0]})
    df['abs'] = df['shap'].abs()
    df['dir'] = df['shap'].apply(lambda x: 'toward_fraud' if x>0 else 'toward_legit')
    return df.nlargest(5,'abs')[['feature','value','shap','dir']].to_dict(orient='records')


def get_db(): return mysql.connector.connect(**DB_CONFIG)

# ── MCP Server ─────────────────────────────────────────────────────────────────
app = Server("fraud-detection")

@app.list_tools()
async def list_tools():
    return [
        # ── STAGE 1 ──────────────────────────────────────────────────────────
        types.Tool(name="flag_transaction", description="""STAGE 1 — TRIAGE GATE. Call this on every incoming transaction before anything else.
Runs lightweight ML + rule engine with zero DB queries to decide if investigation is warranted.

Returns CLEARED or FLAGGED:
  CLEARED → triage score < threshold. Auto-close. Do NOT call any other tools.
            Just call update_case_status(status='auto_cleared').
  FLAGGED → proceed to Stage 2 starting with score_transaction.

Also returns 'suggested_tools' — a hint about which Stage 2 tools are likely relevant
based on which signals fired. Use this to plan your investigation.""",
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"}},"required":["transaction"]}),

        # ── STAGE 2 CORE ──────────────────────────────────────────────────────
        types.Tool(name="score_transaction", description="""STAGE 2 — FULL ML SCORING. Call this first for every FLAGGED transaction.
Runs XGBoost with DB-backed velocity features, isotonic calibration, rule engine, and SHAP.

Returns: ML probability, calibrated probability, final risk score, risk band, recommended action,
triggered rules, top-5 SHAP explanations, and DYNAMIC TOOL GUIDANCE specific to this transaction.

USE THE RETURNED 'DYNAMIC TOOL GUIDANCE' TO DECIDE YOUR NEXT TOOLS.
General rules:
  LOW      → Close. Call add_case_note + update_case_status only.
  MEDIUM   → Call get_customer_profile. Re-evaluate before calling more.
  HIGH     → get_customer_profile + get_recent_txns minimum. Escalate further based on findings.
  CRITICAL → get_device_assoc + get_ip_intelligence as baseline. Then decide based on results.

Always end with add_case_note + update_case_status.""",
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"}},"required":["transaction"]}),

        types.Tool(name="get_customer_profile", description="""STAGE 2 — Customer risk profile. Call for MEDIUM+ bands.
Returns: transaction history, fraud rate, linked cards/devices/emails, velocity stats, known scenarios.
Result tells you whether to also call get_linked_accounts or get_device_assoc.""",
            inputSchema={"type":"object","properties":{"email":{"type":"string"},"card":{"type":"string"},"device_id":{"type":"string"}}}),

        types.Tool(name="get_recent_txns", description="""STAGE 2 — Recent transaction history on card/device/email.
Call for HIGH+ bands, or when velocity rules fired in Stage 1, or when profile shows elevated fraud rate.
Returns: last N transactions with amounts, merchants, timestamps, fraud labels, risk scores.
Result may suggest calling get_device_assoc (velocity burst) or get_linked_accounts (multi-country).""",
            inputSchema={"type":"object","properties":{"card":{"type":"string"},"device_id":{"type":"string"},"email":{"type":"string"},"limit":{"type":"integer"},"hours":{"type":"integer"}}}),

        types.Tool(name="get_device_assoc", description="""STAGE 2 — Device association report.
Call for CRITICAL band, API channel transactions, or when profile/recent_txns suggest multi-card usage.
Returns: all cards and emails linked to this device in last 7 days, fraud rates, ring signal.
If result shows unique_cards >= 5 → call get_linked_accounts.
If ring signal = YES → call get_ip_intelligence.""",
            inputSchema={"type":"object","properties":{"device_id":{"type":"string","description":"Device ID"},"hours":{"type":"integer","description":"Lookback hours (default 168)"}}}),

        # ── STAGE 2 INTELLIGENCE TOOLS ────────────────────────────────────────
        types.Tool(name="get_linked_accounts", description="""STAGE 2 — Cross-identifier fraud ring detection.
Finds all accounts sharing any identifier with this transaction: same IP, same device_id,
same email domain (non-generic), same card BIN prefix (first 6 digits).
Returns: linked accounts, shared identifier type, fraud rates, ring_score.

WHEN TO CALL:
  - device_assoc shows unique_cards >= 3
  - customer profile fraud_rate > 30%
  - triple_country_mismatch fired AND score is HIGH+
  - You suspect organised fraud ring rather than individual card theft""",
            inputSchema={"type":"object","properties":{
                "card":{"type":"string"},"device_id":{"type":"string"},
                "email":{"type":"string"},"ip":{"type":"string"},
                "hours":{"type":"integer","description":"Lookback hours (default 720 = 30 days)"}}}),

        types.Tool(name="get_merchant_risk", description="""STAGE 2 — Merchant fraud intelligence.
Returns: merchant historical fraud rate, last 30-day fraud rate, chargeback trend,
peer comparison vs same MCC category average, watchlist status.

WHEN TO CALL:
  - merchantFraudRate > 0.05 in the transaction payload
  - merchant_country differs from issuer_country
  - Score band is HIGH or CRITICAL
If merchant is on watchlist → escalate regardless of other signals.""",
            inputSchema={"type":"object","properties":{
                "merchant_country":{"type":"string"},"merchant_id":{"type":"string"},
                "merchant_category":{"type":"string"},"merchantFraudRate":{"type":"number"}}}),

        types.Tool(name="get_ip_intelligence", description="""STAGE 2 — IP reputation and geolocation intelligence.
Returns: VPN/proxy/datacenter detection, country mismatch check, historical fraud from this IP
and its /24 subnet, unique cards and emails seen from this IP.

WHEN TO CALL:
  - ip_country != issuer_country
  - authenticationType = not_attempted
  - CRITICAL band
  - device_assoc returns fraud ring signal = YES""",
            inputSchema={"type":"object","properties":{
                "ip":{"type":"string"},"ip_country_long":{"type":"string"},
                "issuerCountryCode":{"type":"string"}}}),

        types.Tool(name="get_similar_fraud_cases", description="""STAGE 2 — Find top-N most similar confirmed fraud cases from history.
Matches on binary flags, auth type, device channel, IP country, and amount range.
Returns: case details, scenario tags, risk scores, similarity scores.

WHEN TO CALL:
  - Unusual signal combination not clearly covered by rules
  - Grey zone: MEDIUM band with conflicting signals
  - You want historical precedent to justify a verdict
  - Checking if this matches a known ongoing fraud campaign""",
            inputSchema={"type":"object","properties":{
                "transaction":{"type":"object"},"top_n":{"type":"integer"},
                "fraud_only":{"type":"boolean"},"scenario_filter":{"type":"string"}}}),

        # ── STAGE 2 CASE MANAGEMENT ───────────────────────────────────────────
        types.Tool(name="add_case_note", description="""STAGE 2 — Append structured analyst note to case record.
Logs the LLM's reasoning, tool findings, and verdict for human analyst audit trail.
ALWAYS call this at the end of every Stage 2 investigation.
Also call mid-investigation when a tool result significantly changes your working hypothesis.""",
            inputSchema={"type":"object","properties":{
                "transaction_id":{"type":"string"},
                "note_type":{"type":"string","enum":["initial_assessment","tool_finding","hypothesis_change","final_verdict","escalation_note"]},
                "content":{"type":"string","description":"Full reasoning — include tools called, what they returned, and your conclusion"},
                "risk_band":{"type":"string"},"confidence":{"type":"number","description":"0.0–1.0"}},
                "required":["transaction_id","note_type","content"]}),

        types.Tool(name="update_case_status", description="""STAGE 2 — Set final case status. ALWAYS call this as the last tool.

Status values:
  auto_cleared       — cleared by Stage 1, no investigation
  closed_legit       — investigated, determined legitimate
  pending_auth       — step-up auth triggered, awaiting customer
  open_case          — escalated to human analyst queue
  blocked_fraud      — blocked, confirmed/highly suspected fraud
  escalated_critical — CRITICAL band, blocked + senior analyst + SAR considered""",
            inputSchema={"type":"object","properties":{
                "transaction_id":{"type":"string"},"status":{"type":"string",
                    "enum":["auto_cleared","closed_legit","pending_auth","open_case","blocked_fraud","escalated_critical"]},
                "risk_band":{"type":"string"},"final_score":{"type":"number"},
                "recommended_action":{"type":"string"},
                "tools_used":{"type":"array","items":{"type":"string"}}},
                "required":["transaction_id","status"]}),
    ]


@app.call_tool()
async def call_tool(name, arguments):
    try:
        h = {"flag_transaction":_flag,"score_transaction":_score,
             "get_customer_profile":_profile,"get_recent_txns":_recent_txns,
             "get_device_assoc":_device_assoc,"get_linked_accounts":_linked_accounts,
             "get_merchant_risk":_merchant_risk,"get_ip_intelligence":_ip_intel,
             "get_similar_fraud_cases":_similar_cases,
             "add_case_note":_add_note,"update_case_status":_update_status}
        if name in h: return await h[name](arguments)
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error in {name}: {str(e)}")]


# ── Stage 1 ────────────────────────────────────────────────────────────────────

async def _flag(args):
    txn = compute_flags(dict(args.get("transaction", {})))
    try:    ts = pd.to_datetime(txn.get('purchase_date', datetime.utcnow().isoformat()))
    except: ts = datetime.utcnow()
    row = dict(txn)
    row.update({'hour_of_day':ts.hour,'day_of_week':ts.dayofweek,
                'is_weekend':int(ts.dayofweek>=5),'is_night':int(ts.hour>=22 or ts.hour<=5)})
    row.setdefault('account_age_min_computed', row.get('account_age_minutes',0))
    for vf in ROLLING_FEATURES: row.setdefault(vf, 0)
    for col in CAT_COLS: row[f'{col}_enc'] = CAT_ENCODINGS.get(col,{}).get(str(row.get(col,'') or ''),0)
    for col in ['card_number','device_id','emailId','ip','mobileNo']: row.setdefault(f'{col}_freq',1)
    raw = triage_score(row)
    row['risk_score'] = round(raw * 190.0, 4)
    feat_df = pd.DataFrame([{col: float(row.get(col) or 0) for col in FEATURE_COLS}])
    ml_prob  = float(MODEL.predict_proba(feat_df)[0, 1])
    cal_prob = float(CALIBRATOR.predict([ml_prob])[0])
    score, fired = apply_rules(cal_prob, txn)
    flagged = score >= TRIAGE_THRESHOLD

    # Build suggested_tools hint
    suggested = []
    if flagged:
        suggested.append("score_transaction")
        if txn.get('f_disposable_email') or txn.get('f_new_account_high_value'):
            suggested.append("get_customer_profile")
        if txn.get('f_triple_country_mismatch') or txn.get('f_ip_issuer_mismatch'):
            suggested.append("get_ip_intelligence")
        if float(txn.get('merchantFraudRate',0)) > 0.05:
            suggested.append("get_merchant_risk")
        if txn.get('f_api_channel'):
            suggested.append("get_device_assoc")
        suggested += ["add_case_note","update_case_status"]

    signals = [k.replace('f_','').replace('_',' ') for k in
               ['f_triple_country_mismatch','f_threeds_failed','f_disposable_email',
                'f_new_account_high_value','f_high_merchant_fraud_rate',
                'f_api_channel','f_high_amount','f_ip_issuer_mismatch'] if txn.get(k)]

    out = f"""TRIAGE GATE RESULT  [STAGE 1]
==============================
Outcome              : {'FLAGGED 🚨' if flagged else 'CLEARED ✅'}
Triage score         : {score:.4f}  (threshold = {TRIAGE_THRESHOLD})
ML probability (raw) : {ml_prob:.4f}
Calibrated prob      : {cal_prob:.4f}

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


# ── Stage 2 core ───────────────────────────────────────────────────────────────

async def _score(args):
    txn = args.get("transaction", {}); db = get_db()
    try:
        feat_df = build_feature_vector(txn, db)
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

        # Dynamic guidance based on band + transaction signals
        mfr = float(txn.get('merchantFraudRate',0))
        guidance_parts = []
        if band == 'LOW':
            guidance_parts = ["Close case. Call add_case_note(note_type='final_verdict') + update_case_status(status='closed_legit')."]
        elif band == 'MEDIUM':
            guidance_parts = ["Call get_customer_profile.",
                              "If profile fraud_rate > 20% → also call get_recent_txns.",
                              "Then add_case_note + update_case_status."]
        elif band == 'HIGH':
            guidance_parts = ["Call get_customer_profile + get_recent_txns.",
                              "If profile fraud_rate > 30% → call get_linked_accounts.",
                              f"{'Call get_merchant_risk (merchantFraudRate elevated). ' if mfr > 0.05 else ''}",
                              "End: add_case_note + update_case_status(status='open_case')."]
        else:  # CRITICAL
            guidance_parts = ["Call get_device_assoc + get_ip_intelligence immediately.",
                              "Then get_customer_profile + get_recent_txns.",
                              "If device shows ring signal → get_linked_accounts.",
                              f"{'Call get_merchant_risk. ' if mfr > 0.05 else ''}",
                              "Consider get_similar_fraud_cases if signal pattern is unusual.",
                              "End: add_case_note + update_case_status(status='escalated_critical')."]

        out = f"""FRAUD SCORING RESULT  [STAGE 2]
================================
Risk score (computed)   : {txn.get('risk_score',0):.2f}
ML probability (raw)    : {ml:.4f}
Calibrated probability  : {cal:.4f}
Final risk score        : {final:.4f}
Risk band               : {band}
Recommended action      : {action}

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


# ── Stage 2 profile tools ──────────────────────────────────────────────────────

async def _profile(args):
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
            return [types.TextContent(type="text", text="No records found for the provided identifier(s).")]
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


async def _recent_txns(args):
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


async def _device_assoc(args):
    did=args.get('device_id'); hours=int(args.get('hours',168))
    if not did: return [types.TextContent(type="text", text="device_id is required")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        since=(datetime.utcnow()-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute("""SELECT COUNT(*) AS tot, COUNT(DISTINCT card_number) AS uc,
            COUNT(DISTINCT email) AS ue, SUM(is_fraud) AS ft, AVG(is_fraud) AS fr,
            MIN(purchase_date) AS fs, MAX(purchase_date) AS ls, MAX(velocity_5min) AS pv
            FROM transactions WHERE device_id=%s AND purchase_date>=%s""",(did,since))
        s=cur.fetchone()
        cur.execute("""SELECT card_number,COUNT(*) AS txns,SUM(is_fraud) AS fraud,MAX(purchase_date) AS lu
            FROM transactions WHERE device_id=%s AND purchase_date>=%s
            GROUP BY card_number ORDER BY txns DESC LIMIT 20""",(did,since))
        cards=cur.fetchall()
        cur.execute("""SELECT email,COUNT(*) AS txns,SUM(is_fraud) AS fraud,MAX(f_disposable_email) AS disp
            FROM transactions WHERE device_id=%s AND purchase_date>=%s
            GROUP BY email ORDER BY txns DESC LIMIT 10""",(did,since))
        emails=cur.fetchall()
        uc=s['uc'] or 0; ue=s['ue'] or 0; fr=float(s['fr'] or 0)*100; ring=uc>=5 or ue>=3
        next_t=[]
        if uc>=5: next_t.append("get_linked_accounts (high card count — fraud ring likely)")
        if ring:  next_t.append("get_ip_intelligence (ring signal detected)")
        lines=[f"DEVICE ASSOCIATION REPORT  [STAGE 2]","="*60,
               f"Device ID        : {did}", f"Lookback         : {hours}h",
               f"Fraud ring signal: {'[!] YES — HIGH RISK' if ring else '[ok] no'}","",
               f"SUMMARY",f"  Total txns   : {s['tot']}",
               f"  Unique cards : {uc}   {'[!] HIGH' if uc>=5 else '[ok]'}",
               f"  Unique emails: {ue}   {'[!] HIGH' if ue>=3 else '[ok]'}",
               f"  Fraud rate   : {fr:.1f}%", f"  Peak velocity: {s['pv']} txns/5min",
               f"  First seen   : {s['fs']}", f"  Last seen    : {s['ls']}", "",
               f"ASSOCIATED CARDS ({len(cards)})"]
        for c in cards:
            lines.append(f"  {str(c['card_number'])[:6]}xxxxxx  txns={c['txns']}  fraud={int(c['fraud'] or 0)}  last={str(c['lu'])[:10]}")
        lines+=["",f"ASSOCIATED EMAILS ({len(emails)})"]
        for e in emails:
            lines.append(f"  {e['email']}{'  [DISPOSABLE]' if e['disp'] else ''}  txns={e['txns']}  fraud={int(e['fraud'] or 0)}")
        lines+=["","SUGGESTED NEXT TOOLS",
                f"  {(chr(10)+'  ').join(next_t) if next_t else 'none — proceed to add_case_note + update_case_status'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()


# ── Stage 2 intelligence tools ─────────────────────────────────────────────────

async def _linked_accounts(args):
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


async def _merchant_risk(args):
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
        lines=[f"MERCHANT RISK PROFILE  [STAGE 2]","="*60,
               f"Merchant country  : {mc or 'N/A'}",f"Merchant category : {mcat or 'N/A'}",
               f"Watchlist status  : {'[!] YES — HIGH RISK' if wl else '[ok] not flagged'}","",
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


async def _ip_intel(args):
    ip=args.get('ip',''); ipc=args.get('ip_country_long',''); isc=args.get('issuerCountryCode','')
    if not ip: return [types.TextContent(type="text", text="ip is required")]
    db=get_db(); cur=db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT COUNT(*) AS tt,SUM(is_fraud) AS ft,AVG(is_fraud) AS fr,
            COUNT(DISTINCT card_number) AS uc,COUNT(DISTINCT email) AS ue,
            MAX(f_datacenter_ip) AS dc,GROUP_CONCAT(DISTINCT ip_country) AS ctry,
            MIN(purchase_date) AS fs,MAX(purchase_date) AS ls
            FROM transactions WHERE ip=%s""",(ip,))
        irow=cur.fetchone()
        subnet='.'.join(ip.split('.')[:3])+'%'
        cur.execute("""SELECT COUNT(*) AS st,SUM(is_fraud) AS sf,AVG(is_fraud) AS sfr,
            COUNT(DISTINCT ip) AS sui FROM transactions WHERE ip LIKE %s AND ip!=%s""",(subnet,ip))
        srow=cur.fetchone()
        ipfr=float(irow['fr'] or 0)*100 if irow and irow['tt'] else None
        sfr=float(srow['sfr'] or 0)*100 if srow and srow['st'] else None
        mismatch=ipc and isc and ipc!='India' and isc=='IND'
        dc=bool(irow and irow['dc'])
        risks=[]
        if mismatch:            risks.append("IP country ≠ issuer country")
        if dc:                  risks.append("Datacenter/cloud IP — bot likely")
        if (ipfr or 0)>20:     risks.append(f"High IP fraud rate ({ipfr:.0f}%)")
        if (sfr or 0)>20:      risks.append(f"High subnet fraud rate ({sfr:.0f}%)")
        if irow and (irow['uc'] or 0)>5: risks.append("Many cards seen from this IP")
        lines=[f"IP INTELLIGENCE REPORT  [STAGE 2]","="*60,
               f"IP address       : {ip}",f"Reported country : {ipc or 'N/A'}",
               f"Issuer country   : {isc or 'N/A'}",
               f"Country mismatch : {'[!] YES' if mismatch else 'no'}",
               f"Datacenter IP    : {'[!] YES — bot/proxy likely' if dc else 'no'}",""]
        if irow and irow['tt']:
            lines+=[f"IP HISTORY",f"  Total txns   : {irow['tt']}",
                    f"  Fraud txns   : {int(irow['ft'] or 0)}  ({ipfr:.1f}%)",
                    f"  Unique cards : {irow['uc']}",f"  Unique emails: {irow['ue']}",
                    f"  Countries    : {irow['ctry']}",""]
        else: lines+=["IP HISTORY       : First-seen — no prior history",""]
        if srow and srow['st']:
            lines+=[f"SUBNET /24",f"  Txns: {srow['st']}  Fraud rate: {sfr:.1f}%  Unique IPs: {srow['sui']}",""]
        lines+=[f"RISK INDICATORS ({len(risks)})",
                f"  {(chr(10)+'  ').join(risks) if risks else 'none'}","",
                f"ANALYST GUIDANCE",
                f"  {'HIGH RISK — weight heavily toward fraud.' if len(risks)>=2 else 'MODERATE — one indicator present.' if risks else 'CLEAN — no IP-level risk signals.'}"]
        return [types.TextContent(type="text", text='\n'.join(lines))]
    finally: cur.close(); db.close()


async def _similar_cases(args):
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


# ── Stage 2 case management ────────────────────────────────────────────────────

async def _add_note(args):
    tid=args.get('transaction_id','unknown'); ntype=args.get('note_type','final_verdict')
    content=args.get('content',''); band=args.get('risk_band','UNKNOWN')
    conf=float(args.get('confidence',0.0))
    if not content: return [types.TextContent(type="text", text="content is required")]
    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO case_notes (transaction_id,note_type,content,risk_band,confidence,created_at)
            VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE content=VALUES(content),
            risk_band=VALUES(risk_band),confidence=VALUES(confidence),created_at=VALUES(created_at)""",
            (tid,ntype,content,band,conf,datetime.utcnow()))
        db.commit(); nid=cur.lastrowid
    except Exception as e: saved=False; err=str(e); nid=0
    finally: cur.close(); db.close()
    out=(f"CASE NOTE ADDED  [STAGE 2]\n===========================\n"
         f"Transaction ID : {tid}\nNote type      : {ntype}\n"
         f"Risk band      : {band}\nConfidence     : {conf:.0%}\n"
         f"Persisted      : {'✅ YES (ID={nid})' if saved else f'⚠️ NO — {err}'}\n"
         f"Timestamp      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n===========================")
    return [types.TextContent(type="text", text=out)]


async def _update_status(args):
    tid=args.get('transaction_id','unknown'); status=args.get('status','open_case')
    band=args.get('risk_band',''); score=float(args.get('final_score',0))
    action=args.get('recommended_action',''); tools=args.get('tools_used',[])
    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO case_status (transaction_id,status,risk_band,final_score,
            recommended_action,tools_used,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE status=VALUES(status),risk_band=VALUES(risk_band),
            final_score=VALUES(final_score),recommended_action=VALUES(recommended_action),
            tools_used=VALUES(tools_used),updated_at=VALUES(updated_at)""",
            (tid,status,band,score,action,json.dumps(tools),datetime.utcnow()))
        db.commit()
    except Exception as e: saved=False; err=str(e)
    finally: cur.close(); db.close()
    emoji={'auto_cleared':'✅','closed_legit':'✅','pending_auth':'⏳',
           'open_case':'📋','blocked_fraud':'🚫','escalated_critical':'🔴'}.get(status,'❓')
    out=(f"CASE STATUS UPDATED  [INVESTIGATION COMPLETE]\n"
         f"=============================================\n"
         f"Transaction ID     : {tid}\n"
         f"Final status       : {emoji} {status.upper()}\n"
         f"Risk band          : {band or 'N/A'}\n"
         f"Final score        : {score:.4f}\n"
         f"Recommended action : {action or 'N/A'}\n"
         f"Tools used ({len(tools)}): {', '.join(tools) if tools else 'N/A'}\n"
         f"Persisted to DB    : {'✅ YES' if saved else f'⚠️ NO — {err}'}\n"
         f"Closed at          : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"=============================================\nInvestigation complete.")
    return [types.TextContent(type="text", text=out)]


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    print("Fraud Detection MCP Server  [Workflow A · Dynamic Tool Edition]", file=sys.stderr)
    print(f"  Stage 1 : flag_transaction  (triage threshold={TRIAGE_THRESHOLD})", file=sys.stderr)
    print(f"  Stage 2 : score_transaction → [LLM decides] → add_case_note + update_case_status", file=sys.stderr)
    print(f"  Tools   : 11 total (1 triage | 4 core | 4 intelligence | 2 case management)", file=sys.stderr)
    print(f"  Features: {len(FEATURE_COLS)}  |  DB: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}", file=sys.stderr)
    print("Ready.\n", file=sys.stderr)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())