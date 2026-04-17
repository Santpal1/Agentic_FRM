"""
Centralized tool routing engine. Single source of truth for determining which tools to call.
Replaces hardcoded if/else across multiple modules.

Maps FLAGS → tools, BANDS → tools, and SHAP features → tools for unified decision-making.
"""

# FLAG to TOOL mapping (Stage 1 routing)
FLAG_TOOL_MAPPING = {
    'f_disposable_email': {
        'tool': 'get_customer_profile',
        'priority': 2,
        'reason': 'Disposable email detected — check transaction history for patterns',
        'always': False
    },
    'f_triple_country_mismatch': {
        'tool': 'get_ip_intelligence',
        'priority': 2,
        'reason': 'Triple country mismatch detected — investigate IP geolocation',
        'always': False
    },
    'f_new_account_high_value': {
        'tool': 'get_customer_profile',
        'priority': 3,
        'reason': 'New account + high value transaction — check account age and patterns',
        'always': False
    },
    'f_frictionless_suspicious': {
        'tool': 'get_customer_profile',
        'priority': 2,
        'reason': 'Frictionless bypass detected (3DS silent pass) — investigate account history',
        'always': False
    },
    'f_api_channel': {
        'tool': 'get_device_assoc',
        'priority': 3,
        'reason': 'API channel detected — check device association patterns',
        'always': False
    },
    'f_datacenter_ip': {
        'tool': 'get_ip_intelligence',
        'priority': 2,
        'reason': 'Datacenter/proxy IP detected — investigate geolocation inconsistencies',
        'always': False
    },
    'f_ip_issuer_mismatch': {
        'tool': 'get_ip_intelligence',
        'priority': 2,
        'reason': 'IP-issuer country mismatch — investigate geolocation',
        'always': False
    },
}

# BAND to TOOL mapping (Stage 2 routing)
BAND_TOOL_MAPPING = {
    'CLEARED': {
        'tools': [],
        'disposition': 'accept',
        'outreach_required': 'no',
        'reason': 'No risk signals detected'
    },
    'LOW': {
        'tools': ['get_merchant_onboarding', 'add_case_note', 'update_case_status'],
        'disposition': 'accept',
        'outreach_required': 'no',
        'reason': 'Low risk — approve directly after merchant confirmation'
    },
    'MEDIUM': {
        'tools': ['get_customer_profile', 'get_merchant_onboarding', 'add_case_note', 'update_case_status'],
        'disposition': 'accept_1fa',
        'outreach_required': 'no',
        'reason': 'Moderate risk — 1FA verification sufficient, no customer outreach needed'
    },
    'HIGH': {
        'tools': ['get_customer_profile', 'get_recent_txns', 'get_merchant_onboarding', 'add_case_note', 'update_case_status'],
        'disposition': 'accept_and_alert',
        'outreach_required': 'conditional',
        'reason': 'High risk — alert merchant if anomaly detected, approve after investigation'
    },
    'CRITICAL': {
        'tools': ['get_device_assoc', 'get_ip_intelligence', 'get_merchant_onboarding', 
                  'get_customer_profile', 'get_recent_txns', 'add_case_note', 'update_case_status'],
        'disposition': 'deny',
        'outreach_required': 'conditional',
        'reason': 'Critical risk — block transaction, conduct thorough investigation'
    }
}

# SHAP FEATURE to TOOL mapping
SHAP_TOOL_MAPPING = {
    'velocity_5min_count': {
        'tools': ['get_recent_txns', 'get_device_assoc'],
        'reason': 'High 5-min velocity burst detected — investigate recent transaction pattern'
    },
    'velocity_1hr_count': {
        'tools': ['get_recent_txns'],
        'reason': 'Sustained 1-hour velocity detected — check transaction velocity pattern'
    },
    'velocity_24hr_count': {
        'tools': ['get_recent_txns', 'get_device_assoc'],
        'reason': 'High 24-hour velocity detected — investigate daily transaction pattern'
    },
    'device_cards_24h': {
        'tools': ['get_device_assoc', 'get_linked_accounts'],
        'reason': 'Multiple cards used on this device in 24h — investigate card ring pattern'
    },
    'email_cards_total': {
        'tools': ['get_customer_profile', 'get_linked_accounts'],
        'reason': 'Email linked to many cards historically — investigate account farming pattern'
    },
    'card_txn_24h': {
        'tools': ['get_recent_txns'],
        'reason': 'High card transaction velocity — investigate recent card usage'
    },
    'merchant_velocity_5min': {
        'tools': ['get_merchant_risk', 'get_recent_txns'],
        'reason': 'Rapid transactions at this merchant — investigate bot/velocity attack pattern'
    },
    'merchantFraudRate': {
        'tools': ['get_merchant_risk', 'get_merchant_onboarding'],
        'reason': 'Merchant has elevated fraud rate — investigate merchant risk profile'
    },
    'account_age_minutes': {
        'tools': ['get_customer_profile'],
        'reason': 'Very new account — investigate account age and patterns'
    },
    'f_threeds_failed': {
        'tools': ['get_customer_profile'],
        'reason': '3DS authentication failed/not attempted — check customer failure pattern'
    },
    'f_datacenter_ip': {
        'tools': ['get_ip_intelligence'],
        'reason': 'Datacenter IP detected — investigate geolocation inconsistencies'
    },
    'f_triple_country_mismatch': {
        'tools': ['get_ip_intelligence'],
        'reason': 'Triple country mismatch — investigate geolocation and IP reputation'
    },
}

# Tool priority levels
TOOL_PRIORITY_LEVELS = {
    'ALWAYS': 1,      # get_merchant_onboarding ALWAYS called before disposition
    'CRITICAL': 2,    # Essential for band decision
    'HIGH': 3,        # Strongly recommended
    'CONDITIONAL': 4, # Only if specific conditions met
    'OPTIONAL': 5     # Nice-to-have for context
}

def get_tools_for_flags(flags_fired, merchant_fraud_rate=0.0):
    """
    Get tool recommendations based on flags fired in Stage 1.
    Returns list of dicts with standardized tool, priority_level, priority_order, reason, source.
    """
    tools = []
    seen = set()
    priority_order_counter = 0
    
    for flag in flags_fired:
        if flag in FLAG_TOOL_MAPPING:
            mapping = FLAG_TOOL_MAPPING[flag]
            tool_name = mapping['tool']
            if tool_name not in seen:
                priority_num = mapping['priority']
                priority_level = 'CRITICAL' if priority_num == 2 else 'HIGH' if priority_num == 3 else 'CONDITIONAL'
                tools.append({
                    'tool': tool_name,
                    'priority_level': priority_level,
                    'priority_order': priority_order_counter,
                    'reason': mapping['reason'],
                    'source': 'flag_signal'
                })
                priority_order_counter += 1
                seen.add(tool_name)
    
    # High merchant fraud rate warrants get_merchant_risk
    if merchant_fraud_rate > 0.05 and 'get_merchant_risk' not in seen:
        tools.append({
            'tool': 'get_merchant_risk',
            'priority_level': 'CRITICAL',
            'priority_order': priority_order_counter,
            'reason': f'Merchant fraud rate elevated at {merchant_fraud_rate:.1%}',
            'source': 'merchant_signal'
        })
        priority_order_counter += 1
        seen.add('get_merchant_risk')
    
    # Add mandatory closure tools
    if not any(t['tool'] in ['add_case_note', 'update_case_status'] for t in tools):
        tools.extend([
            {'tool': 'add_case_note', 'priority_level': 'ALWAYS', 'priority_order': priority_order_counter, 'reason': 'Document investigation findings', 'source': 'mandatory'},
            {'tool': 'update_case_status', 'priority_level': 'ALWAYS', 'priority_order': priority_order_counter + 1, 'reason': 'Close case with final disposition', 'source': 'mandatory'}
        ])
    
    return sorted(tools, key=lambda x: x['priority_order'])


def get_tools_for_band(band, merchant_fraud_rate=0.0, has_ring_signal=False):
    """
    Get tool recommendations based on risk band in Stage 2.
    Returns list of dicts with tool, priority, reason.
    """
    if band not in BAND_TOOL_MAPPING:
        band = 'CRITICAL'
    
    mapping = BAND_TOOL_MAPPING[band]
    tools = []
    seen = set()
    
    for tool in mapping['tools']:
        if tool not in seen:
            priority_level = 'ALWAYS' if tool == 'get_merchant_onboarding' else \
                           'CRITICAL' if tool in mapping['tools'][:3] else 'HIGH' if band == 'CRITICAL' else 'CONDITIONAL'
            tools.append({
                'tool': tool,
                'priority_level': priority_level,
                'priority_order': len(tools),
                'reason': f'{tool} — {band} band investigation',
                'source': 'band_guidance'
            })
            seen.add(tool)
    
    # Conditional tools based on signals
    if merchant_fraud_rate > 0.05 and 'get_merchant_risk' not in seen:
        tools.insert(-2, {  # Insert before add_case_note
            'tool': 'get_merchant_risk',
            'priority_level': 'CONDITIONAL',
            'priority_order': len(tools) - 2,
            'reason': f'Merchant fraud rate at {merchant_fraud_rate:.1%} — investigate merchant risk',
            'source': 'conditional_signal'
        })
        seen.add('get_merchant_risk')
    
    if has_ring_signal and 'get_linked_accounts' not in seen:
        tools.insert(-2, {  # Insert before add_case_note
            'tool': 'get_linked_accounts',
            'priority_level': 'CONDITIONAL',
            'priority_order': len(tools) - 2,
            'reason': 'Fraud ring signal detected — investigate linked accounts',
            'source': 'ring_signal'
        })
        seen.add('get_linked_accounts')
    
    return tools


def get_tools_for_shap_features(shap_features):
    """
    Get tool recommendations based on top SHAP features.
    Returns list of dicts with tool, features, reason, and standardized priority fields.
    """
    tools = {}  # Deduped by tool name
    priority_order_counter = 0
    
    for feature_info in shap_features:
        feature_name = feature_info.get('feature', '')
        if feature_name in SHAP_TOOL_MAPPING:
            mapping = SHAP_TOOL_MAPPING[feature_name]
            for tool in mapping['tools']:
                if tool not in tools:
                    tools[tool] = {
                        'tool': tool,
                        'features': [feature_name],
                        'priority_level': 'HIGH',
                        'priority_order': priority_order_counter,
                        'reason': mapping['reason'],
                        'source': 'shap_analysis'
                    }
                    priority_order_counter += 1
                else:
                    tools[tool]['features'].append(feature_name)
    
    return list(tools.values())


def dedupe_and_prioritize(tool_list):
    """
    Deduplicate tools and sort by priority.
    Later occurrences of same tool keep first occurrence.
    Then sorts by priority_order (lower = higher priority).
    """
    seen = {}
    for tool_spec in tool_list:
        tool_name = tool_spec.get('tool') or tool_spec.get('name')
        if tool_name not in seen:
            seen[tool_name] = tool_spec
    result = list(seen.values())
    return sorted(result, key=lambda x: x.get('priority_order', 99))
