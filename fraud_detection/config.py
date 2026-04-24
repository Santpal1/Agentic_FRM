"""
Configuration constants for fraud detection system.
Includes database config, thresholds, and known datasets.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_CONFIG = {
    'host':     'localhost',
    'port':     3307,
    'user':     'root',
    'password': '',
    'database': 'fraud_detection',
    'charset':  'utf8mb4',
}

# Risk band thresholds (unified and aligned)
TRIAGE_THRESHOLD = 0.25      # CLEARED vs FLAGGED at Stage 1
BAND_CLEARED = 0.25          # Auto-close (no investigation needed)
BAND_LOW    = 0.35           # Low risk (minimal investigation)
BAND_MEDIUM = 0.60           # Medium risk (profile + merchant check)
BAND_HIGH   = 0.80           # High risk (full investigation)
BAND_CRITICAL = 1.0          # Critical risk (block and escalate)

# Case note hard limit (FIX-2)
CASE_NOTE_MAX_CHARS = 400

# Merchant recurrence tracking (FIX-6)
MERCHANT_RECURRENCE_THRESHOLD = 3   # number of CRITICAL flagged txns before escalation
MERCHANT_RECURRENCE_WINDOW_H  = 24  # rolling window in hours

# Transaction history and baseline (new feature)
TRANSACTION_BASELINE_MIN_TXN = 5    # Minimum transactions to compute baseline
TRANSACTION_BASELINE_LOOKBACK_DAYS = 90  # Historical lookback for baseline
ANOMALY_DETECTION_THRESHOLD = 2.0   # Z-score threshold for amount anomaly

# Velocity pattern detection (new feature)
VELOCITY_BURST_5MIN_CRITICAL = 5    # Critical burst in 5 minutes
VELOCITY_BURST_5MIN_HIGH = 3        # High burst in 5 minutes
VELOCITY_BURST_1HR_HIGH = 10        # High sustained velocity in 1 hour
VELOCITY_24HR_SUSTAINED = 20        # Very high daily velocity
GEOGRAPHIC_VELOCITY_COUNTRIES = 2   # Countries in 1 hour = suspicious

# Impossible travel detection (new feature)
IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH = 1500  # km/hr speed threshold
IMPOSSIBLE_TRAVEL_TIME_WINDOW_MIN = 120        # Time window in minutes (2 hours)

# Device fingerprinting (new feature)
DEVICE_SWITCHING_HIGH_THRESHOLD = 4  # More than 4 devices = suspicious
BROWSER_CONSISTENCY_LOW_THRESHOLD = 3  # More than 3 different browsers
SPOOFING_RISK_SCORE_THRESHOLD = 0.30   # Risk score threshold for spoofing

# Feedback and learning (new feature)
FEEDBACK_TYPES = ['false_positive', 'missed_fraud', 'correct_accept', 'correct_deny']
FEEDBACK_FP_RATE_THRESHOLD = 0.30    # FP rate >30% triggers rule review
FEEDBACK_MIN_TRIGGERS_FOR_ANALYSIS = 10  # Minimum triggers to analyze rule
FEEDBACK_LOOKBACK_DAYS = 30          # Days to lookback for performance metrics

# Disposable email domains
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

# Known brand merchants
KNOWN_BRANDS = {
    'tanishq','titan','reliance','tata','hdfc','icici','sbi','airtel','jio','amazon',
    'flipkart','myntra','swiggy','zomato','makemytrip','irctc','ola','uber','phonepe',
    'paytm','razorpay','bigbasket','nykaa','meesho','blinkit','zepto',
}
