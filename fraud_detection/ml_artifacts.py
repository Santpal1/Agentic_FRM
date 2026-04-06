"""
ML artifact loading. Loads model, SHAP explainer, calibrator, and feature metadata.
"""

import sys
import json
import pickle
import os
import numpy as np
from sklearn.isotonic import IsotonicRegression

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("Loading ML artifacts...", file=sys.stderr)

# Load ML models and metadata
with open(os.path.join(BASE_DIR, 'model.pkl'), 'rb') as f:
    MODEL = pickle.load(f)
    
with open(os.path.join(BASE_DIR, 'shap_explainer.pkl'), 'rb') as f:
    EXPLAINER = pickle.load(f)
    
with open(os.path.join(BASE_DIR, 'feature_columns.json'), 'r') as f:
    FEAT_META = json.load(f)
    
with open(os.path.join(BASE_DIR, 'cat_encodings.json'), 'r') as f:
    CAT_ENCODINGS = json.load(f)

FEATURE_COLS     = FEAT_META['feature_cols']
CAT_COLS         = FEAT_META['cat_features']
ROLLING_FEATURES = FEAT_META['rolling_features']
THRESHOLD        = 0.650

print(f"  Model loaded : {len(FEATURE_COLS)} features, threshold={THRESHOLD:.3f}", file=sys.stderr)

# Isotonic calibration for probability scaling
_cal_scores = np.array([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
_cal_probs  = np.array([0.02, 0.05, 0.10, 0.18, 0.28, 0.40, 0.54, 0.68, 0.80, 0.89, 0.94])
CALIBRATOR  = IsotonicRegression(out_of_bounds='clip')
CALIBRATOR.fit(_cal_scores, _cal_probs)
print("  Calibrator ready", file=sys.stderr)
