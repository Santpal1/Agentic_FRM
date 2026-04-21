# 🔗 INTEGRATION GUIDE: Using New Features in Tools

This guide shows how to integrate the new Phase 1 features into your existing fraud detection tools.

---

## 1. Using Merchant Recurrence Tracking

### In `flag_transaction.py` ✅ (Already Updated)
```python
from fraud_detection.merchant_tracking import record_merchant_flag, get_merchant_flag_count

# When flagging a transaction
if flagged:
    merchant_id = txn.get('merchant_id', '')
    transaction_id = txn.get('transaction_id', '')
    merchant_name = txn.get('merchant_name', '')
    
    # Record the flag
    recurrence_count = record_merchant_flag(
        merchant_id,
        transaction_id=transaction_id,
        merchant_name=merchant_name,
        risk_band='FLAGGED'
    )
    
    # Alert if merchant has too many CRITICAL flags
    if recurrence_count >= MERCHANT_RECURRENCE_THRESHOLD:
        alert_user(f"⚠️  {merchant_name} has {recurrence_count} flags in 24h")
```

### In New Tools (To Be Built):
```python
from fraud_detection.merchant_tracking import (
    get_merchant_flag_count,
    get_merchant_recurrence_details
)

# When investigating a merchant
def get_merchant_fraud_history(merchant_id):
    count = get_merchant_flag_count(merchant_id)
    details = get_merchant_recurrence_details(merchant_id)
    return {
        'recent_flags': count,
        'details': details
    }
```

---

## 2. Using Transaction Baseline & Anomaly Detection

### In Tools Like `get_customer_profile.py`:
```python
from fraud_detection.transaction_history import (
    compute_transaction_baseline,
    detect_transaction_anomaly
)

async def enhance_customer_profile(card_number, txn):
    # Compute baseline if not already cached
    baseline = compute_transaction_baseline(card_number)
    
    # Detect anomalies
    anomalies = detect_transaction_anomaly(txn, baseline)
    
    return {
        'baseline_profile': baseline,
        'anomalies': anomalies,
        'summary': {
            'avg_amount': baseline.get('avg_amount'),
            'is_amount_anomaly': anomalies.get('has_anomaly'),
            'anomaly_score': anomalies.get('anomaly_score')
        }
    }
```

### Interpretation:
```
If baseline.avg_amount = 5000 and current txn = 75000:
  → detect_transaction_anomaly() flags 'amount_anomaly_extreme'
  → anomaly_score rises toward 0.5
  → Combined with other signals → higher fraud risk
```

---

## 3. Using Enhanced Velocity Detection

### In Tools Like `get_recent_txns.py`:
```python
from fraud_detection.velocity_patterns import (
    analyze_velocity_patterns,
    detect_impossible_travel
)

async def investigate_velocity(card_number, device_id, current_txn):
    # Analyze pattern type
    patterns = analyze_velocity_patterns(card_number, device_id)
    
    # Check impossible travel
    impossible = detect_impossible_travel(card_number, current_txn)
    
    return {
        'velocity_analysis': {
            'pattern': patterns['pattern_type'],
            'risk_level': patterns['risk_level'],
            'burst_5min': patterns['burst_5min'],
            'burst_1hr': patterns['burst_1hr'],
            'geographic_countries': patterns['geographic_countries']
        },
        'impossible_travel': {
            'detected': impossible['has_impossible_travel'],
            'risk_score': impossible['risk_score'],
            'required_speed': impossible['required_speed_kmh']
        }
    }
```

### Interpretation:
```
Pattern type: 'burst_critical' → 5+ txns in 5 min → card testing
Pattern type: 'merchant_focused_attack' → 3+ txns at same merchant → fraud ring
Impossible travel: True + risk=0.95 → Account takeover (very high confidence)
```

---

## 4. Using Device Fingerprinting

### In Tools Like `get_device_assoc.py`:
```python
from fraud_detection.device_fingerprinting import (
    analyze_device_consistency,
    detect_device_spoofing_signals,
    get_device_linking_graph
)

async def investigate_device(card_number, current_txn):
    # Check device consistency
    consistency = analyze_device_consistency(card_number)
    
    # Check for spoofing signals
    spoofing = detect_device_spoofing_signals(
        current_txn,
        baseline_device_profile=consistency
    )
    
    # Find linked accounts/devices
    graph = get_device_linking_graph(card_number)
    
    return {
        'device_consistency': {
            'switching_frequency': consistency['device_switching_frequency'],
            'browser_consistency': consistency['browser_consistency'],
            'anomalies': consistency['anomaly_flags']
        },
        'spoofing_risk': {
            'has_signals': spoofing['has_spoofing_signals'],
            'risk_score': spoofing['risk_score'],
            'signals': spoofing['signals']
        },
        'linked_accounts': graph['linked_cards']
    }
```

### Interpretation:
```
device_switching_frequency: 'high' → 5+ devices in 30 days → possible card sharing
spoofing_signals: ['bot_user_agent', 'headless_browser'] → automation attack
linked_cards: [card2, card3] → card ring detected
```

---

## 5. Using Feedback Loop

### After Disposition (In Case Management):
```python
from fraud_detection.feedback_tracking import log_feedback

async def close_case(case_id, transaction_id, analyst_notes):
    # After analyst reviews and closes case
    feedback_type = determine_correctness(case_id)  # 'correct_accept', 'correct_deny', etc
    
    log_feedback(
        transaction_id=transaction_id,
        case_id=case_id,
        feedback_type=feedback_type,
        ground_truth='fraud' if fraud_confirmed else 'legitimate',
        system_decision='deny',  # or 'accept', 'review'
        rule_triggered=case['primary_rule'],
        confidence_score=case['final_score'],
        analyst_notes=analyst_notes
    )
```

### Analyzing Rule Effectiveness (Weekly):
```python
from fraud_detection.feedback_tracking import (
    get_rule_effectiveness,
    identify_high_false_positive_rules
)

def generate_rule_report():
    effectiveness = get_rule_effectiveness()
    
    print("\n📊 RULE EFFECTIVENESS REPORT")
    print("=" * 60)
    for rule, stats in sorted(effectiveness.items(), 
                              key=lambda x: x[1]['f1_score'], 
                              reverse=True):
        print(f"{rule:40} Precision:{stats['precision']:.2%}  Recall:{stats['recall']:.2%}  F1:{stats['f1_score']:.2%}")
    
    # Find problematic rules
    problematic = identify_high_false_positive_rules(threshold=0.30, min_triggers=10)
    if problematic:
        print("\n⚠️  HIGH FALSE POSITIVE RULES")
        for rule_info in problematic:
            print(f"  {rule_info['rule']}: {rule_info['fp_rate']:.1%} FP rate ({rule_info['false_positives']} FPs out of {rule_info['total_triggers']} triggers)")
```

---

## 6. Full Workflow Example

### Hypothetical Transaction:
```python
# New transaction: Card 4532XX at Amazon (UK), ₹95,000, 2:15 AM IST
txn = {
    'transaction_id': 'txn_abc123',
    'card_number': '4532XXXXXX',
    'amount_inr': 95000,
    'merchant_id': 'amazon_uk',
    'merchant_country': 'UK',
    'purchase_date': '2026-04-21T02:15:00',
    'ip': '1.2.3.4',
    'ip_country_long': 'UK',
    'device_id': 'new_device_789',
    'browser_ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'authenticationType': 'challenge_success'
}
```

### Stage 1 (Triage) - `flag_transaction.py`:
```
✓ Computed baseline for card
✓ Velocity check: 3 txns in 5 min (burst detected)
✓ Device: New device not seen before (flagged)
✓ Amount: ₹95,000 vs avg ₹15,000 (>2σ)
✓ Time: 2:15 AM (unusual hour)
✓ Country: UK (typical merchant country)

Triage Score: 0.42 (> 0.25 threshold)
STATUS: 🚨 FLAGGED
MERCHANT RECURRENCE: First flag (recorded in DB)
SUGGESTED_TOOLS: score_transaction, get_customer_profile, get_device_assoc
```

### Stage 2 (Scoring) - `score_transaction.py`:
```
✓ Full baseline computed: {avg: 15000, median: 12000, stddev: 5000, devices: 2, ips: 3}
✓ Anomalies detected: {amount_anomaly_extreme, timing_anomaly, device_anomaly_single_user}
✓ Velocity analysis: {pattern: 'burst', risk: 'high', burst_5min: 3, geographic_countries: 2}
✓ Impossible travel: last_txn India 30 min ago, now UK = 13000km needed = IMPOSSIBLE
✓ Device spoofing: Low risk (normal browser UA)

ML Score: 0.74
Final Score: 0.81 (after rules)
RISK BAND: HIGH
DECISION: Require additional verification

ACTION: Call get_customer_profile to verify this is authorized
```

### Resolution:
```
After investigation → Analyst calls update_case_status(disposition='accept_and_alert')

Feedback logged:
- feedback_type: 'correct_accept'
- ground_truth: 'legitimate'
- system_decision: 'HIGH band → review'
- all metrics recorded for rule effectiveness tracking

Merchant recurrence:
- Flag is recorded (1/3 threshold)
- If this repeats 2 more times in 24h → escalate to get_merchant_risk
```

---

## 7. Integration Checklist

- [ ] Database tables created (`python db_setup.py`)
- [ ] Import `merchant_tracking` in tools that handle flagged transactions
- [ ] Import `transaction_history` in `get_customer_profile` tool
- [ ] Import `velocity_patterns` in `get_recent_txns` tool
- [ ] Import `device_fingerprinting` in `get_device_assoc` tool
- [ ] Import `feedback_tracking` in `update_case_status` tool
- [ ] Test each module with sample data
- [ ] Create weekly rule effectiveness report job
- [ ] Create baseline recomputation job (daily for active cards)
- [ ] Monitor performance impact of new features

---

## 8. Performance Considerations

### Computation Cost:
- **Baseline computation**: O(n) where n = historical transactions (capped at 500)
  - Suggested: Cache results, recompute daily
- **Velocity analysis**: O(100) lookups (capped at last 100 txns)
  - Very fast, can run every transaction
- **Impossible travel**: O(1) distance lookup
  - Negligible cost
- **Device fingerprinting**: O(m) where m = recent txn device count
  - Fast, can run every transaction

### Database Queries:
- Add indexes to `merchant_recurrence(merchant_id, flagged_at)`
- Add indexes to `feedback_log(transaction_id, feedback_at)`
- Add indexes to `transaction_baseline(card_number, updated_at)`
- Monitor query times for baseline computation (should be <500ms)

---

**Last Updated**: April 21, 2026
