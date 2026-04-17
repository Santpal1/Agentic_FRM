"""
Flag computation for transaction feature engineering.
FIX-1: Datacenter IP uses two-layer detection. FIX-4: Frictionless bypass flag added.
"""

from fraud_detection.datacenter_detection import _is_datacenter_ip
from fraud_detection.config import DISPOSABLE

def compute_flags(row):
    """
    Compute binary fraud risk flags from transaction fields.
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
    row['f_high_merchant_fraud_rate'] = int(mfr > 0.05)
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
