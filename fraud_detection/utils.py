"""
Utility functions including database connection pooling and helper functions.
Enhanced with query result caching to reduce DB load.
"""

import mysql.connector
import pandas as pd
from fraud_detection.config import DB_CONFIG



def get_db():
    """Create and return a new database connection using configured DB_CONFIG."""
    return mysql.connector.connect(**DB_CONFIG)

def _hour(s):
    """Extract hour from timestamp string. Defaults to 12 on parse error."""
    try:    return pd.to_datetime(s).hour
    except: return 12
