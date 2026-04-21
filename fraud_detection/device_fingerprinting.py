"""
Device fingerprinting module.
Analyzes device consistency, browser characteristics, and potential spoofing.

Note: Limited data available in dataset (browser_ua, device_id only).
      In production, consider integrating with device intelligence APIs.
"""

import hashlib
from fraud_detection.utils import get_db

def extract_browser_fingerprint(browser_ua: str, device_type: str = '') -> dict:
    """
    Extract browser fingerprint from user agent string.
    Limited to available data in current dataset.
    
    Returns:
        Dict with extracted features:
        - os_type: 'windows', 'macos', 'linux', 'ios', 'android'
        - browser_name: 'chrome', 'firefox', 'safari', 'edge', 'unknown'
        - browser_version: Version string
        - device_category: 'mobile', 'tablet', 'desktop'
    """
    fingerprint = {
        'browser_ua_hash': hashlib.sha256(browser_ua.encode()).hexdigest()[:16],
        'os_type': 'unknown',
        'browser_name': 'unknown',
        'browser_version': 'unknown',
        'device_category': device_type or 'unknown'
    }
    
    if not browser_ua:
        return fingerprint
    
    ua_lower = browser_ua.lower()
    
    # OS detection
    if 'windows' in ua_lower:
        fingerprint['os_type'] = 'windows'
    elif 'mac' in ua_lower or 'iphone' in ua_lower:
        fingerprint['os_type'] = 'macos_ios'
    elif 'linux' in ua_lower:
        fingerprint['os_type'] = 'linux'
    elif 'android' in ua_lower:
        fingerprint['os_type'] = 'android'
    
    # Browser detection
    if 'chrome' in ua_lower and 'edge' not in ua_lower:
        fingerprint['browser_name'] = 'chrome'
        start = ua_lower.find('chrome/') + 7
        end = ua_lower.find(' ', start)
        if start > 6 and end > start:
            fingerprint['browser_version'] = ua_lower[start:end]
    elif 'firefox' in ua_lower:
        fingerprint['browser_name'] = 'firefox'
        start = ua_lower.find('firefox/') + 8
        end = ua_lower.find(' ', start)
        if start > 7 and end > start:
            fingerprint['browser_version'] = ua_lower[start:end]
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        fingerprint['browser_name'] = 'safari'
    elif 'edge' in ua_lower or 'edg' in ua_lower:
        fingerprint['browser_name'] = 'edge'
    
    return fingerprint

def analyze_device_consistency(card_number: str, device_id: str = '', 
                              lookback_days: int = 30) -> dict:
    """
    Analyze device consistency for a card over time.
    
    Returns:
        Dict with device consistency metrics:
        - unique_devices: Number of different device IDs
        - unique_browsers: Number of different browser fingerprints
        - unique_os: Number of different OS types
        - device_switching_frequency: How often device changes
        - browser_consistency: How consistent browser characteristics are
        - anomaly_flags: List of suspicious patterns
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    result = {
        'card_number': card_number,
        'device_id': device_id,
        'unique_devices': 0,
        'unique_browsers': 0,
        'unique_os': 0,
        'device_switching_frequency': 'unknown',
        'browser_consistency': 'unknown',
        'anomaly_flags': []
    }
    
    try:
        # Get recent transactions
        cur.execute(f"""
            SELECT device_id, browser_ua, device_type
            FROM transactions
            WHERE card_number = %s 
            AND purchase_date >= DATE_SUB(NOW(), INTERVAL {lookback_days} DAY)
            ORDER BY purchase_date DESC
            LIMIT 100
        """, (card_number,))
        
        txns = cur.fetchall()
        if not txns:
            return result
        
        # Analyze device consistency
        devices = set()
        browsers = set()
        os_types = set()
        fingerprints = []
        
        for txn in txns:
            device = txn.get('device_id', '')
            browser_ua = txn.get('browser_ua', '')
            device_type = txn.get('device_type', '')
            
            if device:
                devices.add(device)
            
            fp = extract_browser_fingerprint(browser_ua, device_type)
            fingerprints.append(fp)
            browsers.add(fp['browser_ua_hash'])
            os_types.add(fp['os_type'])
        
        result['unique_devices'] = len(devices)
        result['unique_browsers'] = len(browsers)
        result['unique_os'] = len(os_types)
        
        # Device switching frequency
        if len(devices) == 1:
            result['device_switching_frequency'] = 'none'
        elif len(devices) <= 2:
            result['device_switching_frequency'] = 'low'
        elif len(devices) <= 4:
            result['device_switching_frequency'] = 'medium'
        else:
            result['device_switching_frequency'] = 'high'
            result['anomaly_flags'].append('excessive_device_switching')
        
        # Browser consistency
        if len(browsers) == 1:
            result['browser_consistency'] = 'high'
        elif len(browsers) <= 2:
            result['browser_consistency'] = 'medium'
        else:
            result['browser_consistency'] = 'low'
            result['anomaly_flags'].append('inconsistent_browser_fingerprint')
        
        # OS consistency
        if len(os_types) > 2 and len(os_types) >= len(devices) * 0.5:
            result['anomaly_flags'].append('os_hopping_detected')
        
        # Desktop/mobile mixing
        device_categories = set(fp['device_category'] for fp in fingerprints 
                              if fp['device_category'] and fp['device_category'] != 'unknown')
        if len(device_categories) > 1:
            result['anomaly_flags'].append('device_type_mixing')
        
    finally:
        cur.close()
        db.close()
    
    return result

def detect_device_spoofing_signals(txn: dict, baseline_device_profile: dict = None) -> dict:
    """
    Detect potential device spoofing or manipulation signals.
    
    Note: Limited to browser UA parsing and basic heuristics.
    In production, integrate with device fingerprinting services (e.g., ThreatMetrix, Iovation).
    
    Returns:
        Dict with spoofing risk indicators:
        - has_spoofing_signals: Boolean
        - risk_score: 0-1
        - signals: List of detected signals
    """
    signals_found = []
    risk_score = 0.0
    
    browser_ua = txn.get('browser_ua', '')
    device_id = txn.get('device_id', '')
    device_type = txn.get('device_type', '')
    
    # Extract fingerprint
    fp = extract_browser_fingerprint(browser_ua, device_type)
    
    # Check for suspicious patterns
    if not browser_ua:
        signals_found.append('missing_browser_ua')
        risk_score += 0.10
    
    # Check for known bot user agents
    bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget']
    if any(indicator in browser_ua.lower() for indicator in bot_indicators):
        signals_found.append('bot_user_agent')
        risk_score += 0.30
    
    # Check for headless browser indicators (likely automation)
    if 'headless' in browser_ua.lower():
        signals_found.append('headless_browser_detected')
        risk_score += 0.25
    
    # Check for inconsistent device type and OS
    ua_lower = browser_ua.lower()
    has_mobile_indicator = any(x in ua_lower for x in ['iphone', 'android', 'mobile'])
    has_desktop_indicator = any(x in ua_lower for x in ['windows', 'macintosh', 'linux'])
    
    if has_mobile_indicator and has_desktop_indicator:
        signals_found.append('conflicting_device_indicators')
        risk_score += 0.15
    
    if device_type and device_type.lower() == 'desktop' and 'mobile' in browser_ua.lower():
        signals_found.append('device_type_ua_mismatch')
        risk_score += 0.10
    
    # Compare with baseline if available
    if baseline_device_profile:
        if fp['os_type'] != baseline_device_profile.get('typical_os'):
            signals_found.append('os_change')
            risk_score += 0.08
        
        if fp['browser_name'] != baseline_device_profile.get('typical_browser'):
            signals_found.append('browser_change')
            risk_score += 0.05
    
    return {
        'has_spoofing_signals': len(signals_found) > 0,
        'risk_score': min(risk_score, 1.0),
        'signals': signals_found,
        'fingerprint': fp
    }

def get_device_linking_graph(card_number: str, lookback_days: int = 90) -> dict:
    """
    Build device linking graph for a card.
    Shows relationships between devices, IPs, and other cards.
    
    Returns:
        Dict with graph information:
        - primary_devices: Main devices used
        - linked_cards: Other cards sharing devices/IPs
        - shared_ips: IPs shared with other cards
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    result = {
        'card_number': card_number,
        'primary_devices': [],
        'linked_cards': [],
        'shared_ips': []
    }
    
    try:
        # Get devices for this card
        cur.execute(f"""
            SELECT DISTINCT device_id, COUNT(*) as count
            FROM transactions
            WHERE card_number = %s 
            AND purchase_date >= DATE_SUB(NOW(), INTERVAL {lookback_days} DAY)
            GROUP BY device_id
            ORDER BY count DESC
            LIMIT 5
        """, (card_number,))
        
        result['primary_devices'] = [
            {'device_id': r['device_id'], 'transaction_count': r['count']} 
            for r in cur.fetchall()
        ]
        
        # Find other cards using same devices
        devices = [d['device_id'] for d in result['primary_devices']]
        if devices:
            placeholders = ','.join(['%s'] * len(devices))
            cur.execute(f"""
                SELECT DISTINCT card_number, COUNT(*) as count
                FROM transactions
                WHERE device_id IN ({placeholders})
                AND card_number != %s
                GROUP BY card_number
                ORDER BY count DESC
                LIMIT 10
            """, devices + [card_number])
            
            result['linked_cards'] = [
                {'card_number': r['card_number'], 'shared_txn_count': r['count']}
                for r in cur.fetchall()
            ]
        
        # Get IPs for this card
        cur.execute(f"""
            SELECT DISTINCT ip, COUNT(*) as count
            FROM transactions
            WHERE card_number = %s 
            AND purchase_date >= DATE_SUB(NOW(), INTERVAL {lookback_days} DAY)
            GROUP BY ip
            ORDER BY count DESC
            LIMIT 5
        """, (card_number,))
        
        ips = [r['ip'] for r in cur.fetchall()]
        result['shared_ips'] = ips
        
    finally:
        cur.close()
        db.close()
    
    return result
