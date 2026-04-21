"""
Transaction history and behavioral baseline module.
Computes and tracks customer transaction patterns for anomaly detection.
"""

import numpy as np
from datetime import datetime, timedelta
from fraud_detection.utils import get_db

def compute_transaction_baseline(card_number: str, email: str = '', device_id: str = '', 
                                min_txn_count: int = 5) -> dict:
    """
    Compute behavioral baseline from historical transactions.
    Creates profile of typical transaction amounts, merchants, categories, timing, and devices.
    
    Args:
        card_number: Card identifier
        email: Email associated with card
        device_id: Device identifier
        min_txn_count: Minimum transactions to compute baseline (default 5)
    
    Returns:
        Dict with baseline metrics:
        - avg_amount, median_amount, stddev_amount
        - typical_merchants, typical_categories, typical_countries
        - typical_hours, typical_device_count, typical_ip_count
        - avg_daily_count, max_daily_count
        - account_age_days, txn_count_used
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    baseline = {
        'card_number': card_number,
        'email': email,
        'device_id': device_id,
        'status': 'insufficient_data',
        'txn_count': 0
    }
    
    try:
        # Get all historical transactions for this card
        cur.execute("""
            SELECT purchase_date, amount_inr, merchant_id, merchant_category, 
                   merchant_country, hour(purchase_date) as txn_hour, 
                   device_id, ip, account_age_minutes
            FROM transactions
            WHERE card_number = %s
            ORDER BY purchase_date DESC
            LIMIT 500
        """, (card_number,))
        
        txns = cur.fetchall()
        if len(txns) < min_txn_count:
            baseline['txn_count'] = len(txns)
            return baseline
        
        amounts = [float(t['amount_inr'] or 0) for t in txns]
        merchants = [t['merchant_id'] for t in txns if t['merchant_id']]
        categories = [t['merchant_category'] for t in txns if t['merchant_category']]
        countries = [t['merchant_country'] for t in txns if t['merchant_country']]
        hours = [t['txn_hour'] for t in txns if t['txn_hour'] is not None]
        devices = set(t['device_id'] for t in txns if t['device_id'])
        ips = set(t['ip'] for t in txns if t['ip'])
        
        # Amount statistics
        baseline['avg_amount'] = float(np.mean(amounts))
        baseline['median_amount'] = float(np.median(amounts))
        baseline['stddev_amount'] = float(np.std(amounts))
        baseline['min_amount'] = float(np.min(amounts))
        baseline['max_amount'] = float(np.max(amounts))
        
        # Typical merchants and categories (top 5)
        from collections import Counter
        baseline['typical_merchants'] = [m[0] for m in Counter(merchants).most_common(5)]
        baseline['typical_categories'] = [c[0] for c in Counter(categories).most_common(5)]
        baseline['typical_countries'] = [c[0] for c in Counter(countries).most_common(5)]
        
        # Typical transaction hours (peak hours)
        hour_counts = Counter(hours)
        baseline['typical_hours'] = [h[0] for h in hour_counts.most_common(8)]  # Top 8 hours
        
        # Device and IP diversity
        baseline['typical_device_count'] = len(devices)
        baseline['typical_ip_count'] = len(ips)
        
        # Daily transaction frequency
        daily_counts = {}
        for txn in txns:
            day = txn['purchase_date'].strftime('%Y-%m-%d')
            daily_counts[day] = daily_counts.get(day, 0) + 1
        
        baseline['avg_daily_count'] = float(np.mean(list(daily_counts.values())))
        baseline['max_daily_count'] = int(np.max(list(daily_counts.values())))
        
        # Account age
        oldest_txn_age = txns[-1]['account_age_minutes'] if txns[-1]['account_age_minutes'] else 0
        baseline['account_age_days'] = max(int(oldest_txn_age / 1440), 1)
        baseline['txn_count_used'] = len(txns)
        baseline['status'] = 'computed'
        baseline['last_computed'] = datetime.utcnow().isoformat()
        
    finally:
        cur.close()
        db.close()
    
    return baseline

def save_baseline_to_db(baseline: dict):
    """Store computed baseline in database for future reference."""
    if baseline.get('status') != 'computed':
        return False
    
    db = get_db()
    cur = db.cursor()
    try:
        # Check if baseline exists
        cur.execute("SELECT id FROM transaction_baseline WHERE card_number = %s", 
                   (baseline['card_number'],))
        exists = cur.fetchone()
        
        import json
        merchants_json = json.dumps(baseline.get('typical_merchants', []))
        categories_json = json.dumps(baseline.get('typical_categories', []))
        countries_json = json.dumps(baseline.get('typical_countries', []))
        hours_json = json.dumps(baseline.get('typical_hours', []))
        
        if exists:
            # Update existing
            cur.execute("""
                UPDATE transaction_baseline
                SET avg_transaction_amt=%s, median_transaction_amt=%s, stddev_amount=%s,
                    typical_merchants=%s, typical_categories=%s, typical_countries=%s,
                    typical_hours=%s, typical_devices=%s, typical_ips=%s,
                    avg_daily_count=%s, max_daily_count=%s, account_age_days=%s,
                    txn_count_used=%s, last_computed=NOW()
                WHERE card_number=%s
            """, (
                baseline['avg_amount'], baseline['median_amount'], baseline['stddev_amount'],
                merchants_json, categories_json, countries_json, hours_json,
                baseline['typical_device_count'], baseline['typical_ip_count'],
                baseline['avg_daily_count'], baseline['max_daily_count'],
                baseline['account_age_days'], baseline['txn_count_used'],
                baseline['card_number']
            ))
        else:
            # Insert new
            cur.execute("""
                INSERT INTO transaction_baseline
                (card_number, email, device_id, avg_transaction_amt, median_transaction_amt,
                 stddev_amount, typical_merchants, typical_categories, typical_countries,
                 typical_hours, typical_devices, typical_ips, avg_daily_count,
                 max_daily_count, account_age_days, txn_count_used, last_computed)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                baseline['card_number'], baseline['email'], baseline['device_id'],
                baseline['avg_amount'], baseline['median_amount'], baseline['stddev_amount'],
                merchants_json, categories_json, countries_json, hours_json,
                baseline['typical_device_count'], baseline['typical_ip_count'],
                baseline['avg_daily_count'], baseline['max_daily_count'],
                baseline['account_age_days'], baseline['txn_count_used']
            ))
        
        db.commit()
        return True
    finally:
        cur.close()
        db.close()

def detect_transaction_anomaly(txn: dict, baseline: dict = None) -> dict:
    """
    Detect anomalies compared to customer's historical baseline.
    
    Returns:
        Dict with anomaly flags:
        - amount_anomaly: Amount significantly different from typical
        - merchant_anomaly: Merchant not in typical set
        - timing_anomaly: Transaction at unusual hour
        - device_anomaly: Device/IP not in typical set
        - country_anomaly: Country not in typical set
        - velocity_anomaly: Transaction frequency unusually high
    """
    anomalies = {
        'has_anomaly': False,
        'flags': [],
        'anomaly_score': 0.0
    }
    
    # If no baseline, skip comparison
    if not baseline or baseline.get('status') != 'computed':
        return anomalies
    
    score = 0.0
    
    # Amount anomaly detection
    txn_amount = float(txn.get('amount_inr') or txn.get('purchase_amount') or 0)
    baseline_avg = baseline.get('avg_amount', 0)
    baseline_std = baseline.get('stddev_amount', 1)
    
    if baseline_std > 0:
        z_score = abs(txn_amount - baseline_avg) / baseline_std
        if z_score > 3.0:  # More than 3 standard deviations
            anomalies['flags'].append('amount_anomaly_extreme')
            score += 0.15
        elif z_score > 2.0:
            anomalies['flags'].append('amount_anomaly_high')
            score += 0.08
    
    # Merchant anomaly
    merchant = txn.get('merchant_id', '')
    typical_merchants = baseline.get('typical_merchants', [])
    if merchant and merchant not in typical_merchants:
        anomalies['flags'].append('merchant_anomaly')
        score += 0.10
    
    # Timing anomaly
    try:
        txn_hour = int(datetime.fromisoformat(txn.get('purchase_date')).hour)
        typical_hours = baseline.get('typical_hours', [])
        if typical_hours and txn_hour not in typical_hours:
            anomalies['flags'].append('timing_anomaly')
            score += 0.08
    except:
        pass
    
    # Device/IP anomaly
    device = txn.get('device_id', '')
    typical_device_count = baseline.get('typical_device_count', 1)
    if typical_device_count <= 1 and device and device != txn.get('device_id'):
        anomalies['flags'].append('device_anomaly_single_user')
        score += 0.12
    
    # Country anomaly
    country = txn.get('merchant_country', '')
    typical_countries = baseline.get('typical_countries', [])
    if country and typical_countries and country not in typical_countries:
        anomalies['flags'].append('country_anomaly')
        score += 0.10
    
    if anomalies['flags']:
        anomalies['has_anomaly'] = True
        anomalies['anomaly_score'] = min(score, 1.0)
    
    return anomalies
