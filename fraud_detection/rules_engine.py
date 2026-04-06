"""
Rule engine for fraud detection. Includes scoring rules, risk banding, and merchant trust tier logic.
"""

import numpy as np
import pandas as pd
from fraud_detection.config import BAND_LOW, BAND_MEDIUM, BAND_HIGH, KNOWN_BRANDS
from fraud_detection.utils import _hour

# Define all fraud detection rules with their conditions and delta adjustments
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

def apply_rules(cal_prob, txn):
    """
    Apply all rules to transaction and accumulate delta adjustments.
    Returns final score (clipped 0.0-1.0) and list of fired rule names with deltas.
    """
    adj, fired = 0.0, []
    for name, cond, delta in RULES:
        try:
            if cond(txn): adj += delta; fired.append(f"{name} ({delta:+.2f})")
        except: pass
    return float(np.clip(cal_prob + adj, 0.0, 1.0)), fired

def risk_band(s):
    """
    Map risk score to risk band (LOW, MEDIUM, HIGH, CRITICAL).
    Bands determine disposition guidance and tool chain.
    """
    if s < BAND_LOW:    return 'LOW'
    if s < BAND_MEDIUM: return 'MEDIUM'
    if s < BAND_HIGH:   return 'HIGH'
    return 'CRITICAL'

def rec_action(band):
    """
    Map risk band to recommended action for LLM guidance.
    Encodes disposition and outreach philosophy per band.
    """
    return {'LOW':      'accept — low risk, approve directly',
            'MEDIUM':   'accept_1fa — approve after OTP/biometric (no further outreach)',
            'HIGH':     'accept_and_alert or deny — check merchant type before deciding',
            'CRITICAL': 'deny — block transaction, review outreach necessity'}[band]

def get_merchant_trust_tier(merchant_name: str, merchant_id: str = '') -> str:
    """
    Assign merchant to trust tier (known_brand, registered, unknown).
    known_brand merchants get disposition protections in Stage 2.
    """
    name_lower = (merchant_name or '').lower()
    if any(brand in name_lower for brand in KNOWN_BRANDS):
        return 'known_brand'
    if merchant_id:
        return 'registered'
    return 'unknown'

def disposition_guidance(band: str, merchant_trust_tier: str, mfr: float) -> dict:
    """
    Provide LLM-facing guidance on disposition based on risk band, merchant tier, and fraud rate.
    Encodes business rules for known-brand protection, HIGH-band merchant routing, CRITICAL escalation.
    """
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
