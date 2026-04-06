"""
Configuration constants for fraud detection system.
Includes database config, thresholds, and known datasets.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_CONFIG = {
    'host':     'localhost',
    'port':     3306,
    'user':     'root',
    'password': '',
    'database': 'fraud_detection',
    'charset':  'utf8mb4',
}

# Risk band thresholds
TRIAGE_THRESHOLD = 0.25
BAND_LOW    = 0.30
BAND_MEDIUM = 0.60
BAND_HIGH   = 0.80

# Case note hard limit (FIX-2)
CASE_NOTE_MAX_CHARS = 400

# Merchant recurrence tracking (FIX-6)
MERCHANT_RECURRENCE_THRESHOLD = 3   # number of CRITICAL flagged txns before escalation
MERCHANT_RECURRENCE_WINDOW_H  = 24  # rolling window in hours

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
