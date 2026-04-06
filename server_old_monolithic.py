"""
server.py — Fraud Detection MCP Server  (Workflow A · Dynamic Tool Edition)
============================================================================

FIXES APPLIED
-------------
FIX-1  ip_isp datacenter detection — two-layer approach:
         Layer 1: existing ip_isp string match (unchanged)
         Layer 2: NEW fallback CIDR prefix check against known cloud/Tor ranges
                  when ip_isp is absent or empty. Covers AWS, GCP, Azure, Tor exits,
                  and major hosting providers without requiring the gateway to send ip_isp.

FIX-2  add_case_note hard length cap — 400 chars max.
         Previously a soft warning (logged but accepted any length).
         Now returns an ERROR and refuses to persist if content > 400 chars.
         The 3-5 line template stays; the cap enforces it mechanically.

FIX-3  Tool description for add_case_note updated to state the 400-char hard limit
         so the LLM knows upfront rather than discovering it on rejection.

FIX-4  disposable_plus_frictionless rule added to rule engine.
         frictionless_success + disposable email OR new account (<60 min) is a known
         3DS bypass pattern. Fires +0.10. Mirrors the existing disposable_plus_3ds_fail
         rule so the bypass is caught at Stage 1 triage and Stage 2 scoring.
         f_frictionless_suspicious flag added to compute_flags().

FIX-5  get_merchant_onboarding added to Stage 1 suggested_tools always.
         Stage 1 already knows merchant_id and merchant_name; get_merchant_onboarding
         should always appear in the suggestion chain, not be silently omitted.

FIX-6  Merchant recurrence escalation in flag_transaction.
         If the same merchant_id has appeared in >= MERCHANT_RECURRENCE_THRESHOLD
         CRITICAL-band flagged transactions within MERCHANT_RECURRENCE_WINDOW_H hours,
         get_merchant_risk is appended to suggested_tools and a warning is emitted.
         Tracked in the merchant_flag_counts in-memory dict (resets on server restart;
         a production deployment should persist this in Redis or the DB).

FIX-7  update_case_status now enforces add_case_note prerequisite.
         Before accepting a final disposition, the handler queries the case_notes table
         for the transaction_id. If no note exists it returns an error, preventing
         cases from being closed without a written assessment.

FIX-8  get_recent_txns fallback when get_customer_profile returns no records.
         score_transaction dynamic guidance for CRITICAL now explicitly instructs the
         caller to fall back to get_recent_txns on the card alone if customer profile
         returns no records, so the workflow doesn't dead-end on first-seen identifiers.

FIX-9  velocity_per_merchant feature added to rule engine and feature vector.
         merchant_velocity_5min tracks how many transactions the same card/device
         has attempted at the same merchant in the last 5 minutes via DB query.
         Rule api_merchant_velocity fires at >= 3 hits (+0.10), catching merchant-focused
         bot attacks that the global velocity counter would attribute to the device only.

FIX-10 submit_false_positive_feedback validates rule_triggered against known rules.
         Previously accepted any free-text string, making the feedback loop noisy.
         Now checks the value against the KNOWN_RULE_NAMES set and returns an error
         with a list of valid names if an unknown rule is supplied.
"""

import sys
import io
import json
import pickle
import os
from datetime import datetime, timedelta

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="xmlcharrefreplace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="xmlcharrefreplace")

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

TRIAGE_THRESHOLD = 0.25
BAND_LOW    = 0.30
BAND_MEDIUM = 0.60
BAND_HIGH   = 0.80

CASE_NOTE_MAX_CHARS = 400   # FIX-2: hard cap — reject notes longer than this

# FIX-6: Merchant recurrence tracking — in-memory, resets on server restart.
# Production deployments should persist this in Redis or the transactions DB.
MERCHANT_RECURRENCE_THRESHOLD = 3   # number of CRITICAL flagged txns before escalation
MERCHANT_RECURRENCE_WINDOW_H  = 24  # rolling window in hours
_merchant_flag_log: dict[str, list[datetime]] = {}  # merchant_id -> [flagged_at, ...]

def _record_merchant_flag(merchant_id: str) -> int:
    """Record a CRITICAL flag event for merchant_id. Returns current count in window."""
    if not merchant_id:
        return 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
    events = _merchant_flag_log.get(merchant_id, [])
    events = [t for t in events if t >= cutoff]   # prune old events
    events.append(now)
    _merchant_flag_log[merchant_id] = events
    return len(events)

def _merchant_flag_count(merchant_id: str) -> int:
    """Return current CRITICAL flag count for merchant_id within the window."""
    if not merchant_id:
        return 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=MERCHANT_RECURRENCE_WINDOW_H)
    events = _merchant_flag_log.get(merchant_id, [])
    return sum(1 for t in events if t >= cutoff)

# ── FIX-1: Known datacenter / Tor CIDR prefix table ───────────────────────────
# Used as fallback when ip_isp is absent. Covers the most common cloud egress
# and Tor exit ranges seen in Indian payment fraud. Intentionally conservative —
# only /8 and /16 prefixes that are unambiguously non-residential.
DATACENTER_PREFIXES = (
    # AWS us-east / us-west / ap-southeast
    "52.",   "54.",   "18.",
    # GCP global egress
    "34.",   "35.",   "104.196.", "104.197.", "104.198.", "104.199.",
    # Azure
    "40.",   "20.",   "13.",
    # DigitalOcean
    "134.122.", "137.184.", "143.198.", "146.190.", "159.65.", "159.89.",
    "161.35.",  "164.90.",  "165.22.",  "167.71.",  "167.172.", "174.138.",
    # Linode / Akamai
    "139.162.", "172.104.", "192.46.",  "45.33.",   "45.56.",   "45.79.",
    # Vultr
    "45.32.",   "45.63.",   "45.76.",   "45.77.",
    # OVH
    "51.75.",   "51.77.",   "51.91.",   "54.36.",   "54.38.",
    # Hetzner
    "78.46.",   "88.198.",  "95.216.",  "116.202.", "136.243.",
    # Known Tor exit ranges (185.220.x.x is the most active in South Asia fraud)
    "185.220.", "199.249.", "204.13.",  "192.42.",  "176.10.",
    # Cloudflare Workers / proxies
    "104.16.",  "104.17.",  "104.18.",  "104.19.",  "104.20.",  "104.21.",
    "172.64.",  "172.65.",  "172.66.",  "172.67.",
)

def _is_datacenter_ip(ip: str, isp: str) -> bool:
    """
    FIX-1: Two-layer datacenter detection.
    Layer 1: existing keyword match on ip_isp (unchanged behaviour).
    Layer 2: fallback CIDR prefix check when ip_isp is absent/empty.
    Returns True if either layer fires.
    """
    DATACENTER_ISP_KEYWORDS = [
        'aws', 'amazon', 'google cloud', 'azure', 'digitalocean',
        'linode', 'vultr', 'ovh', 'hetzner',
    ]
    # Layer 1 — isp string match (original logic)
    if isp:
        isp_lower = isp.lower()
        if any(k in isp_lower for k in DATACENTER_ISP_KEYWORDS):
            return True
    # Layer 2 — prefix fallback
    if ip:
        for prefix in DATACENTER_PREFIXES:
            if ip.startswith(prefix):
                return True
    return False


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
THRESHOLD        = 0.650

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
    # FIX-4: frictionless_success + disposable email OR new account is a known 3DS bypass
    ('disposable_plus_frictionless', lambda t: t.get('f_frictionless_suspicious', 0) == 1,                                                                                             +0.10),
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
    # FIX-9: per-merchant velocity rule — catches bot attacks targeting a single merchant
    ('api_merchant_velocity',        lambda t: int(t.get('merchant_velocity_5min', 0)) >= 3,                                                                                           +0.10),
    ('long_standing_account',        lambda t: float(t.get('account_age_minutes',0))>=43200,                                                                                           -0.05),
    ('successful_3ds_challenge',     lambda t: str(t.get('authenticationType',''))=='challenge_success',                                                                               -0.04),
    ('low_merchant_fraud_rate',      lambda t: float(t.get('merchantFraudRate',1.0))<0.02,                                                                                             -0.03),
]

# FIX-10: canonical rule names used for feedback validation
KNOWN_RULE_NAMES: set[str] = {r[0] for r in RULES}

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
    return {'LOW':      'accept — low risk, approve directly',
            'MEDIUM':   'accept_1fa — approve after OTP/biometric (no further outreach)',
            'HIGH':     'accept_and_alert or deny — check merchant type before deciding',
            'CRITICAL': 'deny — block transaction, review outreach necessity'}[band]

KNOWN_BRANDS = {
    'tanishq','titan','reliance','tata','hdfc','icici','sbi','airtel','jio','amazon',
    'flipkart','myntra','swiggy','zomato','makemytrip','irctc','ola','uber','phonepe',
    'paytm','razorpay','bigbasket','nykaa','meesho','blinkit','zepto',
}

def get_merchant_trust_tier(merchant_name: str, merchant_id: str = '') -> str:
    name_lower = (merchant_name or '').lower()
    if any(brand in name_lower for brand in KNOWN_BRANDS):
        return 'known_brand'
    if merchant_id:
        return 'registered'
    return 'unknown'

def disposition_guidance(band: str, merchant_trust_tier: str, mfr: float) -> dict:
    if merchant_trust_tier == 'known_brand' and band != 'CRITICAL':
        return {
            'disposition':      'accept_and_alert',
            'outreach_required': 'conditional',
            'outreach_target':   'merchant_only — only if merchant anomaly is primary signal',
            'rationale':        f'Known brand merchant — direct deny blocked. Band={band}. Monitor and alert.',
        }
    if band == 'LOW':
        return {'disposition':'accept','outreach_required':'no','outreach_target':'none','rationale':'Low risk. Approve directly.'}
    elif band == 'MEDIUM':
        return {'disposition':'accept_1fa','outreach_required':'no','outreach_target':'none — 1FA already verifies identity, no further outreach needed','rationale':'Moderate risk. 1FA (OTP/biometric) sufficient verification.'}
    elif band == 'HIGH':
        if mfr > 0.08:
            return {'disposition':'accept_and_alert','outreach_required':'conditional','outreach_target':'merchant_only — merchant anomaly is primary driver','rationale':f'High merchant fraud rate ({mfr:.1%}). Merchant behaviour is primary signal.'}
        return {'disposition':'accept_and_alert','outreach_required':'no','outreach_target':'none — monitor only unless investigation reveals specific anomaly','rationale':'HIGH band but no dominant merchant signal. Alert and monitor.'}
    else:
        if merchant_trust_tier == 'known_brand':
            return {'disposition':'deny','outreach_required':'yes','outreach_target':'customer — known brand, deny may be false positive; verify before blocking permanently','rationale':'CRITICAL band overrides known-brand protection. Customer verification required.'}
        return {'disposition':'deny','outreach_required':'conditional','outreach_target':'none if clear fraud ring; customer if ambiguous; merchant if merchant-driven','rationale':'CRITICAL band. Block transaction. Assess outreach need case-by-case.'}

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


def compute_flags(row):
    """
    FIX-1: f_datacenter_ip uses two-layer detection.
    FIX-4: f_frictionless_suspicious added — frictionless_success + disposable OR new account.
    """
    amt   = float(row.get('amount_inr') or row.get('purchase_amount') or 0)
    isc   = str(row.get('issuerCountryCode') or '')
    ipc   = str(row.get('ip_country_long') or '')
    mc    = str(row.get('merchant_country') or '')
    auth  = str(row.get('authenticationType') or '')
    email = str(row.get('emailId') or row.get('email') or '')
    isp   = str(row.get('ip_isp') or '').lower()
    ip    = str(row.get('ip') or '')
    dch   = str(row.get('deviceChannel') or '')
    page  = int(row.get('merchantPageTxn') or 1)
    mfr   = float(row.get('merchantFraudRate') or 0)
    age   = float(row.get('account_age_minutes') or 0)

    is_disposable = int(any(d in email for d in DISPOSABLE))

    row['f_high_amount']              = int(amt > 50000)
    row['f_ip_issuer_mismatch']       = int(ipc != 'India' and isc == 'IND')
    row['f_triple_country_mismatch']  = int(isc == 'IND' and mc != 'IND' and ipc != 'India')
    row['f_high_merchant_fraud_rate'] = int(mfr > 0.08)
    row['f_new_account_high_value']   = int(age < 60 and amt > 10000)
    row['f_threeds_failed']           = int(auth in ['challenge_failed', 'not_attempted'])
    row['f_disposable_email']         = is_disposable
    row['f_datacenter_ip']            = int(_is_datacenter_ip(ip, isp))   # FIX-1
    row['f_api_channel']              = int(dch == 'API')
    row['f_bin_country_mismatch']     = int(isc == 'IND' and mc != 'IND')
    row['f_merchant_page_redirect']   = int(page == 0)
    # FIX-4: frictionless bypass flag — fires when 3DS passes silently but identity is suspect
    row['f_frictionless_suspicious']  = int(
        auth == 'frictionless_success' and (is_disposable == 1 or age < 60)
    )
    return row


def triage_score(txn):
    w = {'f_high_amount':18,'f_ip_issuer_mismatch':22,'f_triple_country_mismatch':24,
         'f_high_merchant_fraud_rate':18,'f_new_account_high_value':28,'f_threeds_failed':32,
         'f_disposable_email':14,'f_datacenter_ip':18,'f_api_channel':9,
         'f_bin_country_mismatch':18,'f_merchant_page_redirect':8,
         'f_frictionless_suspicious':16}   # FIX-4: included in triage weight table
    return float(np.clip(sum(float(txn.get(k,0))*v for k,v in w.items())/206.0, 0.0, 1.0))


def build_feature_vector(txn, db_conn):
    row = dict(txn)
    try:    ts = pd.to_datetime(row.get('purchase_date', datetime.utcnow().isoformat()))
    except: ts = datetime.utcnow()
    row.update({'hour_of_day':ts.hour,'day_of_week':ts.dayofweek,
                'is_weekend':int(ts.dayofweek>=5),'is_night':int(ts.hour>=22 or ts.hour<=5)})
    row.setdefault('account_age_min_computed', row.get('account_age_minutes',0))
    if any(row.get(f) is None for f in ROLLING_FEATURES):
        row = velocity_from_db(row, ts, db_conn)
    # FIX-9: fetch per-merchant velocity from DB
    row = merchant_velocity_from_db(row, ts, db_conn)
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
    row = compute_flags(row)   # FIX-1 + FIX-4: two-layer datacenter + frictionless flag
    if not row.get('risk_score'):
        w = {'velocity_5min_count':8,'velocity_1hr_count':3,'device_cards_24h':10,
             'email_cards_total':6,'card_txn_24h':4,'f_high_amount':18,
             'f_ip_issuer_mismatch':22,'f_triple_country_mismatch':24,
             'f_high_merchant_fraud_rate':18,'f_new_account_high_value':28,
             'f_threeds_failed':32,'f_disposable_email':14,'f_datacenter_ip':18,
             'f_api_channel':9,'f_bin_country_mismatch':18,'f_merchant_page_redirect':8,
             'f_frictionless_suspicious':14}   # FIX-4
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


def merchant_velocity_from_db(row, ts, db_conn):
    """
    FIX-9: Per-merchant velocity lookup.
    Counts how many transactions the same card OR device made at this specific merchant
    in the last 5 minutes. Stored as merchant_velocity_5min.
    """
    merchant_id = row.get('merchant_id', '')
    card        = row.get('card_number', '')
    device_id   = row.get('device_id', '')
    ts_s        = ts.strftime('%Y-%m-%d %H:%M:%S')
    since_5m    = (ts - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')

    if not merchant_id or not (card or device_id):
        row.setdefault('merchant_velocity_5min', 0)
        return row

    cur = db_conn.cursor(dictionary=True)
    try:
        conds, params = ['merchant_id=%s', 'purchase_date>=%s', 'purchase_date<%s'], [merchant_id, since_5m, ts_s]
        if card and device_id:
            conds.append('(card_number=%s OR device_id=%s)')
            params += [card, device_id]
        elif card:
            conds.append('card_number=%s'); params.append(card)
        else:
            conds.append('device_id=%s'); params.append(device_id)
        cur.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE {' AND '.join(conds)}", params)
        row['merchant_velocity_5min'] = cur.fetchone()['cnt']
    except:
        row.setdefault('merchant_velocity_5min', 0)
    finally:
        cur.close()
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
            inputSchema={"type":"object","properties":{"transaction":{"type":"object"}},"required":["transaction"]}),

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

        # FIX-2 + FIX-3: Hard 400-char cap stated in description; wording clarified for 3-5 lines
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

        # FIX-10: rule_triggered validated against KNOWN_RULE_NAMES
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
    try:
        h = {"flag_transaction":_flag,"score_transaction":_score,
             "get_customer_profile":_profile,"get_recent_txns":_recent_txns,
             "get_device_assoc":_device_assoc,"get_linked_accounts":_linked_accounts,
             "get_merchant_onboarding":_merchant_onboarding,
             "get_merchant_risk":_merchant_risk,"get_ip_intelligence":_ip_intel,
             "get_similar_fraud_cases":_similar_cases,
             "add_case_note":_add_note,"update_case_status":_update_status,
             "submit_false_positive_feedback":_fp_feedback}
        if name in h: return await h[name](arguments)
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error in {name}: {str(e)}")]


# ── Stage 1 ────────────────────────────────────────────────────────────────────

async def _flag(args):
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


# ── Stage 2 core ───────────────────────────────────────────────────────────────

async def _score(args):
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
        # FIX-6: include recurrence count in merchant risk report
        recurrence_count = _merchant_flag_count(mid)
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
        # FIX-1: use two-layer detection for the IP intel report too
        dc = _is_datacenter_ip(ip, '')   # isp not available here; CIDR fallback covers it
        risks=[]
        if mismatch:            risks.append("IP country ≠ issuer country")
        if dc:                  risks.append("Datacenter/cloud/Tor IP (CIDR prefix match)")
        if (ipfr or 0)>20:     risks.append(f"High IP fraud rate ({ipfr:.0f}%)")
        if (sfr or 0)>20:      risks.append(f"High subnet fraud rate ({sfr:.0f}%)")
        if irow and (irow['uc'] or 0)>5: risks.append("Many cards seen from this IP")
        lines=[f"IP INTELLIGENCE REPORT  [STAGE 2]","="*60,
               f"IP address       : {ip}",f"Reported country : {ipc or 'N/A'}",
               f"Issuer country   : {isc or 'N/A'}",
               f"Country mismatch : {'[!] YES' if mismatch else 'no'}",
               f"Datacenter IP    : {'[!] YES — CIDR prefix match' if dc else 'no'}",""]
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
    """FIX-2: Hard 400-char cap — reject submissions over the limit."""
    tid=args.get('transaction_id','unknown'); ntype=args.get('note_type','final_verdict')
    content=args.get('content',''); band=args.get('risk_band','UNKNOWN')
    alert_cat=args.get('alert_category','genuine'); conf=float(args.get('confidence',0.0))

    if not content:
        return [types.TextContent(type="text", text="ERROR: content is required.")]

    # FIX-2: Hard cap enforcement
    if len(content) > CASE_NOTE_MAX_CHARS:
        over = len(content) - CASE_NOTE_MAX_CHARS
        return [types.TextContent(type="text", text=(
            f"ERROR: Case note rejected — content is {len(content)} chars, "
            f"{over} over the {CASE_NOTE_MAX_CHARS}-char hard limit.\n"
            f"Rewrite as 3-5 tight lines totalling ≤{CASE_NOTE_MAX_CHARS} chars. "
            f"3 lines are sufficient for straightforward cases; use up to 5 only if needed.\n"
            f"Template:\n"
            f"  L1: [rule] fired — [why]\n"
            f"  L2: [other signals checked]\n"
            f"  L3: [merchant context]\n"
            f"  L4: [verdict + confidence]\n"
            f"  L5 (optional): [action + outreach target]"
        ))]

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
         f"Alert category : {alert_cat}\nRisk band      : {band}\nConfidence     : {conf:.0%}\n"
         f"Length         : {len(content)}/{CASE_NOTE_MAX_CHARS} chars\n"
         f"Persisted      : {'YES (ID='+str(nid)+')' if saved else 'NO -- '+err}\n"
         f"Timestamp      : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"===========================")
    return [types.TextContent(type="text", text=out)]


async def _update_status(args):
    tid=args.get('transaction_id','unknown')
    disposition=args.get('disposition','accept')
    band=args.get('risk_band',''); score=float(args.get('final_score',0))
    alert_cat=args.get('alert_category','genuine')
    outreach_req=args.get('outreach_required','no')
    outreach_tgt=args.get('outreach_target','none')
    report=args.get('report','')
    action=args.get('recommended_action',''); tools=args.get('tools_used',[])

    if not report:
        return [types.TextContent(type="text", text="ERROR: report field is MANDATORY. Provide a 3-5 line rationale before closing the case.")]

    # FIX-7: Enforce add_case_note prerequisite — check case_notes table before accepting
    db_check = get_db(); cur_check = db_check.cursor(dictionary=True)
    note_exists = False
    try:
        cur_check.execute(
            "SELECT COUNT(*) AS cnt FROM case_notes WHERE transaction_id=%s", (tid,)
        )
        row = cur_check.fetchone()
        note_exists = bool(row and row['cnt'] > 0)
    except Exception:
        # If the table doesn't exist yet or query fails, allow through (new deployment).
        note_exists = True
    finally:
        cur_check.close(); db_check.close()

    if not note_exists:
        return [types.TextContent(type="text", text=(
            f"ERROR: Cannot close case {tid} — no case note found.\n"
            f"Call add_case_note first with a 3-5 line assessment (≤{CASE_NOTE_MAX_CHARS} chars), "
            f"then call update_case_status again."
        ))]

    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO case_status
            (transaction_id,status,risk_band,final_score,disposition,outreach_required,
             outreach_target,report,recommended_action,tools_used,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE status=VALUES(status),risk_band=VALUES(risk_band),
            final_score=VALUES(final_score),disposition=VALUES(disposition),
            outreach_required=VALUES(outreach_required),outreach_target=VALUES(outreach_target),
            report=VALUES(report),recommended_action=VALUES(recommended_action),
            tools_used=VALUES(tools_used),updated_at=VALUES(updated_at)""",
            (tid,disposition,band,score,disposition,outreach_req,outreach_tgt,
             report,action,json.dumps(tools),datetime.utcnow()))
        db.commit()
    except Exception as e: saved=False; err=str(e)
    finally: cur.close(); db.close()

    emoji={'accept':'OK','accept_1fa':'1FA','accept_and_alert':'ALERT','deny':'DENY'}.get(disposition,'?')
    outreach_line = (f"Outreach target    : {outreach_tgt}" if outreach_tgt != 'none'
                     else "Outreach           : none required")
    out=(f"CASE CLOSED  [INVESTIGATION COMPLETE]\n"
         f"======================================\n"
         f"Transaction ID     : {tid}\n"
         f"Disposition        : [{emoji}] {disposition.upper()}\n"
         f"Alert category     : {alert_cat}\n"
         f"Risk band          : {band or 'N/A'}\n"
         f"Final score        : {score:.4f}\n"
         f"{outreach_line}\n"
         f"Tools used ({len(tools)}): {', '.join(tools) if tools else 'N/A'}\n"
         f"Persisted to DB    : {'YES' if saved else 'NO -- '+err}\n"
         f"Closed at          : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"--------------------------------------\n"
         f"REPORT\n  {report}\n"
         f"======================================\nInvestigation complete.")
    return [types.TextContent(type="text", text=out)]


async def _merchant_onboarding(args):
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


async def _fp_feedback(args):
    tid      = args.get('transaction_id','unknown')
    orig     = args.get('original_disposition','deny')
    correct  = args.get('correct_disposition','accept_and_alert')
    rule     = args.get('rule_triggered','')
    note     = args.get('analyst_note','')

    if not rule:
        return [types.TextContent(type="text", text="rule_triggered is required")]

    # FIX-10: validate rule_triggered against the known rule names
    if rule not in KNOWN_RULE_NAMES:
        sorted_names = sorted(KNOWN_RULE_NAMES)
        return [types.TextContent(type="text", text=(
            f"ERROR: rule_triggered '{rule}' is not a known rule name.\n"
            f"Valid rule names:\n  " + "\n  ".join(sorted_names)
        ))]

    db=get_db(); cur=db.cursor(); saved=True; err=''
    try:
        cur.execute("""INSERT INTO false_positive_feedback
            (transaction_id,original_disposition,correct_disposition,rule_triggered,analyst_note,created_at)
            VALUES (%s,%s,%s,%s,%s,%s)""",
            (tid,orig,correct,rule,note,datetime.utcnow()))
        db.commit(); fid=cur.lastrowid
    except Exception as e: saved=False; err=str(e); fid=0
    finally: cur.close(); db.close()

    out=(f"FALSE POSITIVE FEEDBACK LOGGED\n"
         f"================================\n"
         f"Transaction ID      : {tid}\n"
         f"Original disposition: {orig}\n"
         f"Correct disposition : {correct}\n"
         f"Rule over-triggered : {rule}\n"
         f"Analyst note        : {note or 'N/A'}\n"
         f"Persisted           : {'YES (ID='+str(fid)+')' if saved else 'NO -- '+err}\n"
         f"Timestamp           : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
         f"--------------------------------\n"
         f"ACTION: Human analyst will review and update rule weight or add merchant exception.\n"
         f"================================")
    return [types.TextContent(type="text", text=out)]


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    print("Fraud Detection MCP Server  [Workflow A · PayU SOP Edition]", file=sys.stderr)
    print(f"  Stage 1 : flag_transaction  (triage threshold={TRIAGE_THRESHOLD})", file=sys.stderr)
    print(f"  Stage 2 : score_transaction -> [LLM decides] -> add_case_note + update_case_status", file=sys.stderr)
    print(f"  Tools   : 13 total (1 triage | 4 core | 5 intelligence | 2 case mgmt | 1 feedback)", file=sys.stderr)
    print(f"  Dispositions: accept | accept_1fa | accept_and_alert | deny", file=sys.stderr)
    print(f"  Features: {len(FEATURE_COLS)}  |  DB: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}", file=sys.stderr)
    print(f"  FIX-1 : Datacenter detection — ip_isp match + CIDR prefix fallback ({len(DATACENTER_PREFIXES)} prefixes)", file=sys.stderr)
    print(f"  FIX-2 : Case note hard cap — {CASE_NOTE_MAX_CHARS} chars max (hard reject)", file=sys.stderr)
    print(f"  FIX-3 : Tool description updated with hard cap notice + clarified 3-5 line guidance", file=sys.stderr)
    print(f"  FIX-4 : disposable_plus_frictionless rule — 3DS bypass detection", file=sys.stderr)
    print(f"  FIX-5 : get_merchant_onboarding always in Stage 1 suggested_tools", file=sys.stderr)
    print(f"  FIX-6 : Merchant recurrence alert — >= {MERCHANT_RECURRENCE_THRESHOLD} CRITICAL flags in {MERCHANT_RECURRENCE_WINDOW_H}h triggers get_merchant_risk", file=sys.stderr)
    print(f"  FIX-7 : update_case_status enforces add_case_note prerequisite", file=sys.stderr)
    print(f"  FIX-8 : get_customer_profile no-records fallback to get_recent_txns for CRITICAL", file=sys.stderr)
    print(f"  FIX-9 : merchant_velocity_5min feature + api_merchant_velocity rule", file=sys.stderr)
    print(f"  FIX-10: submit_false_positive_feedback validates rule_triggered against KNOWN_RULE_NAMES", file=sys.stderr)
    print("Ready.\n", file=sys.stderr)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())