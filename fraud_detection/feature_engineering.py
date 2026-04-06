"""
Feature engineering, triage scoring, and SHAP explanation. 
Builds feature vectors for ML model and computes top-5 feature importances.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from fraud_detection.utils import get_db, _hour
from fraud_detection.ml_artifacts import MODEL, EXPLAINER, CALIBRATOR, FEATURE_COLS, CAT_COLS, ROLLING_FEATURES, CAT_ENCODINGS
from fraud_detection.flags import compute_flags

def triage_score(txn):
    """
    Compute lightweight triage score from binary flags (Stage 1).
    Used at initial gate before expensive Stage 2 scoring.
    """
    w = {'f_high_amount':18,'f_ip_issuer_mismatch':22,'f_triple_country_mismatch':24,
         'f_high_merchant_fraud_rate':18,'f_new_account_high_value':28,'f_threeds_failed':32,
         'f_disposable_email':14,'f_datacenter_ip':18,'f_api_channel':9,
         'f_bin_country_mismatch':18,'f_merchant_page_redirect':8,
         'f_frictionless_suspicious':16}   # FIX-4: included in triage weight table
    return float(np.clip(sum(float(txn.get(k,0))*v for k,v in w.items())/206.0, 0.0, 1.0))

def build_feature_vector(txn, db_conn):
    """
    Build complete feature vector for ML scoring (Stage 2).
    Computes time-based fields, velocity metrics, flag encodings, categorical encodings.
    FIX-1 + FIX-4 + FIX-9: datacenter, frictionless, and per-merchant velocity included.
    """
    from fraud_detection.velocity import velocity_from_db, merchant_velocity_from_db
    
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

def shap_top5(feat_df):
    """
    Compute top-5 SHAP feature importances for explainability.
    Returns list of dicts with feature name, value, SHAP score, and direction (toward_fraud vs toward_legit).
    """
    sv = EXPLAINER.shap_values(feat_df)
    df = pd.DataFrame({'feature':FEATURE_COLS,'value':feat_df.values[0],'shap':sv[0]})
    df['abs'] = df['shap'].abs()
    df['dir'] = df['shap'].apply(lambda x: 'toward_fraud' if x>0 else 'toward_legit')
    return df.nlargest(5,'abs')[['feature','value','shap','dir']].to_dict(orient='records')
