"""
Enhanced velocity pattern detection.
Distinguishes between burst attacks, sustained velocity, and geographic velocity anomalies.
"""

from datetime import datetime, timedelta
import numpy as np
from fraud_detection.utils import get_db

def analyze_velocity_patterns(card_number: str, device_id: str = '', 
                              merchant_id: str = '') -> dict:
    """
    Analyze velocity patterns to distinguish attack types.
    
    Returns:
        Dict with pattern analysis:
        - burst_5min: Count of transactions in last 5 minutes
        - burst_1hr: Count of transactions in last hour
        - sustained_24h: Count over 24 hours
        - pattern_type: 'burst', 'sustained', 'normal', 'escalating'
        - geographic_spread: Number of unique countries in recent txns
        - merchant_focused: True if velocity concentrated at single merchant
        - device_consistency: True if all recent txns from same device
        - risk_level: 'low', 'medium', 'high', 'critical'
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    patterns = {
        'card_number': card_number,
        'device_id': device_id,
        'merchant_id': merchant_id,
        'pattern_type': 'unknown',
        'risk_level': 'low'
    }
    
    try:
        now = datetime.utcnow()
        
        # Get recent transactions
        cur.execute("""
            SELECT purchase_date, merchant_id, merchant_country, device_id, ip
            FROM transactions
            WHERE card_number = %s
            ORDER BY purchase_date DESC
            LIMIT 100
        """, (card_number,))
        
        recent_txns = cur.fetchall()
        if not recent_txns:
            return patterns
        
        # Burst detection (5 min)
        burst_5min_time = now - timedelta(minutes=5)
        burst_5min = sum(1 for t in recent_txns 
                        if t['purchase_date'] >= burst_5min_time)
        patterns['burst_5min'] = burst_5min
        
        # Burst detection (1 hour)
        burst_1hr_time = now - timedelta(hours=1)
        burst_1hr = sum(1 for t in recent_txns 
                       if t['purchase_date'] >= burst_1hr_time)
        patterns['burst_1hr'] = burst_1hr
        
        # Sustained velocity (24 hours)
        sustained_24h_time = now - timedelta(hours=24)
        sustained_24h = sum(1 for t in recent_txns 
                           if t['purchase_date'] >= sustained_24h_time)
        patterns['sustained_24h'] = sustained_24h
        
        # Pattern type classification
        if burst_5min >= 5:
            patterns['pattern_type'] = 'burst_critical'
            patterns['risk_level'] = 'critical'
        elif burst_5min >= 3:
            patterns['pattern_type'] = 'burst'
            patterns['risk_level'] = 'high'
        elif burst_1hr >= 10:
            patterns['pattern_type'] = 'escalating'
            patterns['risk_level'] = 'high'
        elif sustained_24h > 15:
            patterns['pattern_type'] = 'sustained_high'
            patterns['risk_level'] = 'medium'
        else:
            patterns['pattern_type'] = 'normal'
            patterns['risk_level'] = 'low'
        
        # Geographic velocity
        recent_1hr = [t for t in recent_txns 
                     if t['purchase_date'] >= burst_1hr_time]
        unique_countries = set(t['merchant_country'] for t in recent_1hr 
                              if t['merchant_country'])
        patterns['geographic_countries'] = len(unique_countries)
        
        if len(unique_countries) > 2:
            patterns['geographic_velocity'] = 'high'
            if burst_1hr >= 3:
                patterns['risk_level'] = 'critical'  # Multiple countries + velocity = account takeover
        
        # Merchant concentration
        merchant_ids = [t['merchant_id'] for t in recent_1hr if t['merchant_id']]
        if merchant_ids:
            unique_merchants = len(set(merchant_ids))
            patterns['merchant_focused'] = (unique_merchants == 1 and len(merchant_ids) >= 3)
            patterns['unique_merchants_1hr'] = unique_merchants
            
            if patterns['merchant_focused']:
                # Card testing or bot attack at specific merchant
                patterns['pattern_type'] = 'merchant_focused_attack'
                patterns['risk_level'] = 'high'
        
        # Device consistency
        devices = set(t['device_id'] for t in recent_1hr if t['device_id'])
        patterns['device_consistency'] = (len(devices) <= 1)
        patterns['unique_devices_1hr'] = len(devices)
        
        # Velocity anomaly score (0-1)
        anomaly_score = 0.0
        if burst_5min >= 5:
            anomaly_score = min(0.95, 0.6 + (burst_5min - 5) * 0.1)
        elif burst_1hr >= 10:
            anomaly_score = min(0.85, 0.5 + (burst_1hr - 10) * 0.05)
        elif sustained_24h > 20:
            anomaly_score = min(0.70, 0.3 + (sustained_24h - 20) * 0.02)
        
        patterns['velocity_anomaly_score'] = float(anomaly_score)
        patterns['detected_at'] = now.isoformat()
        
    finally:
        cur.close()
        db.close()
    
    return patterns

def detect_impossible_travel(card_number: str, current_txn: dict) -> dict:
    """
    Detect impossible travel patterns (multiple countries/cities in unrealistic timeframes).
    
    Returns:
        Dict with impossible travel detection:
        - has_impossible_travel: Boolean
        - last_txn_location: (country, city)
        - current_location: (country, city)
        - time_diff_minutes: Minutes between last txn and current
        - required_speed_kmh: Speed required to travel between locations
        - is_impossible: True if physical travel impossible
        - risk_score: 0-1 indicating likelihood of account takeover
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    result = {
        'has_impossible_travel': False,
        'risk_score': 0.0
    }
    
    try:
        # Get last transaction for this card
        cur.execute("""
            SELECT purchase_date, merchant_country, ip_country_long, ip_city
            FROM transactions
            WHERE card_number = %s
            ORDER BY purchase_date DESC
            LIMIT 1
        """, (card_number,))
        
        last_txn = cur.fetchone()
        if not last_txn:
            return result
        
        # Current transaction location
        current_country = current_txn.get('merchant_country') or current_txn.get('ip_country_long')
        current_city = current_txn.get('ip_city', '')
        current_time = datetime.fromisoformat(current_txn.get('purchase_date'))
        
        # Last transaction location
        last_country = last_txn.get('merchant_country') or last_txn.get('ip_country_long')
        last_city = last_txn.get('ip_city', '')
        last_time = last_txn['purchase_date']
        
        result['last_txn_location'] = (last_country, last_city)
        result['current_location'] = (current_country, current_city)
        
        # Time difference
        time_diff = (current_time - last_time).total_seconds() / 60  # minutes
        result['time_diff_minutes'] = int(time_diff)
        
        # Only check if different countries and within 24 hours
        if last_country == current_country or time_diff > 1440:
            return result
        
        # Simple heuristic: assume average travel speed of 900 km/hr (commercial flight)
        # Known distances between major countries
        country_distances = {
            ('India', 'USA'): 13000,
            ('India', 'UK'): 7000,
            ('India', 'Singapore'): 3000,
            ('USA', 'UK'): 5500,
            ('USA', 'Singapore'): 13600,
            ('UK', 'Singapore'): 10900
        }
        
        distance_key = tuple(sorted([last_country, current_country]))
        distance_km = country_distances.get(distance_key, 5000)  # Default 5000 km
        
        # Speed required to travel in given time
        required_speed = distance_km / max(time_diff / 60, 0.1)  # km/hr
        result['required_speed_kmh'] = int(required_speed)
        
        # Commercial flights ~900 km/hr, impossible if > 1500 km/hr
        result['is_impossible'] = required_speed > 1500
        
        if result['is_impossible'] and time_diff < 120:  # Less than 2 hours
            result['has_impossible_travel'] = True
            result['risk_score'] = 0.95  # Very high confidence
        elif required_speed > 1000 and time_diff < 300:  # Less than 5 hours
            result['has_impossible_travel'] = True
            result['risk_score'] = 0.75
        
    finally:
        cur.close()
        db.close()
    
    return result

def save_velocity_pattern(pattern: dict):
    """Store velocity pattern analysis in database for investigation."""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO velocity_patterns
            (card_number, device_id, merchant_id, pattern_type, 
             burst_count_5min, burst_count_1hr, sustained_velocity_24h,
             geographic_countries, anomaly_score, detected_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            pattern.get('card_number'),
            pattern.get('device_id'),
            pattern.get('merchant_id'),
            pattern.get('pattern_type'),
            pattern.get('burst_5min', 0),
            pattern.get('burst_1hr', 0),
            pattern.get('sustained_24h', 0),
            pattern.get('geographic_countries', 0),
            pattern.get('velocity_anomaly_score', 0)
        ))
        db.commit()
    finally:
        cur.close()
        db.close()
