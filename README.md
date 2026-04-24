# Agentic Fraud Detection & Risk Management System

A modular, AI-powered fraud detection system built with an agentic architecture. Combines machine learning models, business rules, and intelligent tool orchestration to investigate and score transactions in real-time.

> 🎬 **[Watch Demo Video](https://drive.google.com/file/d/1GR9qUUWBVmSuGV6pCRrGXjAy2iAy9De3/view?usp=sharing)** — See the full fraud detection workflow in action.

---

## 📋 Table of Contents

- [Demo](#demo)
- [Overview](#overview)
- [Architecture](#architecture)
- [Key Components](#key-components)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Available Tools](#available-tools)
- [Configuration](#configuration)
- [Development](#development)

---

## Demo

[![Watch Demo](https://img.shields.io/badge/▶_Watch_Demo-Google_Drive-blue?style=for-the-badge)](https://drive.google.com/file/d/1GR9qUUWBVmSuGV6pCRrGXjAy2iAy9De3/view?usp=sharing)

Full walkthrough of a transaction going through:
- **Stage 1** — Triage Gate (`flag_transaction`) with zero DB queries
- **Stage 2** — Full ML Scoring (`score_transaction`) with DB-backed velocity features
- **Investigation Tools** — `get_customer_profile`, `get_ip_intelligence`, `get_merchant_onboarding`, and more
- **Case Closure** — `add_case_note` + `update_case_status` with final disposition

---

## Overview

This system provides:

- **Real-time Fraud Scoring**: ML-based risk scoring with explainability (SHAP)
- **Agentic Investigation**: Tool-driven workflow that intelligently selects which investigations to run
- **Rules Engine**: Customizable business rules with configurable thresholds
- **Merchant Risk Tracking**: Velocity analysis and recurrence detection
- **Comprehensive Case Management**: Add notes, update status, submit feedback
- **Adaptive Routing**: Smart tool selection based on risk flags and ML features

---

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────┐
│       server.py (MCP Server)            │
│  (Orchestrates tools & workflows)       │
└────────────┬────────────────────────────┘
             │
   ┌─────────┴──────────────────────────────────────────┐
   │                                                      │
   ▼                                                      ▼
┌──────────────────────┐                    ┌────────────────────────┐
│ Fraud Detection Core │                    │  Investigation Tools   │
│                      │                    │                        │
│ • ML Scoring         │                    │ • Customer Profiles    │
│ • Rules Engine       │                    │ • Device Associations  │
│ • Feature Engineer   │                    │ • IP Intelligence      │
│ • Velocity Analysis  │                    │ • Merchant Risk        │
│                      │                    │ • Transaction History  │
└──────────┬───────────┘                    │ • Case Management      │
           │                                 │ • Feedback System      │
           └─────────────────┬───────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  MySQL Database │
                    └─────────────────┘
```

### Module Structure

```
fraud_detection/
├── config.py                    # Configuration constants & thresholds
├── ml_artifacts.py              # ML model and SHAP explainer loading
├── feature_engineering.py       # Feature vector construction
├── rules_engine.py              # Business rule evaluation
├── flags.py                     # Flag generation logic
├── velocity.py                  # Velocity & recurrence tracking
├── merchant_tracking.py         # Merchant risk aggregation
├── datacenter_detection.py      # IP datacenter identification
├── tool_router.py               # Central routing engine (flags → tools)
├── utils.py                     # Shared utilities & DB connection
└── tools/                       # Individual tool implementations (13 tools)
    ├── flag_transaction.py
    ├── score_transaction.py
    ├── get_customer_profile.py
    ├── get_device_assoc.py
    ├── get_ip_intelligence.py
    ├── get_linked_accounts.py
    ├── get_merchant_onboarding.py
    ├── get_merchant_risk.py
    ├── get_recent_txns.py
    ├── get_similar_fraud_cases.py
    ├── add_case_note.py
    ├── update_case_status.py
    └── submit_false_positive_feedback.py
```

---

## Key Components

### 1. **ML Scoring Engine** (`ml_artifacts.py`)
- Loads pre-trained machine learning models
- Generates SHAP explanations for model predictions
- Provides confidence scores and feature importance rankings

### 2. **Rules Engine** (`rules_engine.py`)
- Customizable business rules with configurable triggers
- Supports disposable email detection, velocity anomalies, frictionless bypasses, and more
- Generates risk flags that feed into tool routing

### 3. **Feature Engineering** (`feature_engineering.py`)
- Constructs rich feature vectors from transaction data
- Includes velocity metrics, merchant patterns, device history
- Normalizes features for ML model input

### 4. **Tool Router** (`tool_router.py`)
- Central decision engine for tool orchestration
- Maps detected flags to specific investigation tools
- Optimizes investigation cost and latency

### 5. **Velocity Analysis** (`velocity.py`)
- Tracks transaction patterns per device, merchant, country
- Detects anomalies and recurrence
- Merchant escalation when CRITICAL flags exceed threshold

### 6. **Investigation Tools** (`tools/`)
- 13 modular tools for different investigation aspects
- Examples: customer profiles, device associations, IP intelligence, merchant risk
- Each tool returns structured, actionable insights

---

## Setup & Installation

### Prerequisites

- **Python 3.8+**
- **MySQL 5.7+** (for transaction and case data)
- **Git** (for version control)

### Step 1: Clone & Setup

```bash
# Clone repository
git clone https://github.com/Santpal1/Agentic_FRM.git
cd Agentic_FRM

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Configure Database

Update `fraud_detection/config.py` with your MySQL credentials:

```python
DB_CONFIG = {
    'host':     'your_host',
    'port':     3306,
    'user':     'your_user',
    'password': 'your_password',
    'database': 'fraud_detection',
    'charset':  'utf8mb4',
}
```

Run database setup:

```bash
python db_setup.py
```

### Step 4: Load ML Models

Place trained ML models in the root directory:
- `model.pkl` — Fraud detection model
- `shap_explainer.pkl` — SHAP explainer

### Step 5: Start the Server

```bash
python server.py
```

The MCP server will start and expose investigation tools to connected AI agents.

---

## Usage

> 📺 Prefer a visual walkthrough? **[Watch the demo video](https://drive.google.com/file/d/1GR9qUUWBVmSuGV6pCRrGXjAy2iAy9De3/view?usp=sharing)** before reading the code examples below.

### Basic Transaction Investigation

```python
from fraud_detection.tools.score_transaction import score_transaction

# Score a transaction
result = score_transaction(
    transaction_id="txn_12345",
    customer_id="cust_6789",
    amount=5000.00,
    merchant="amazon.com",
    timestamp="2026-04-21T10:30:00Z"
)

# Returns:
# {
#     "risk_band": "HIGH",
#     "fraud_score": 0.75,
#     "flags": ["f_new_account_high_value", "f_triple_country_mismatch"],
#     "suggested_tools": ["get_customer_profile", "get_ip_intelligence"],
#     "investigation_cost": 0.18
# }
```

### Case Management

```python
from fraud_detection.tools.add_case_note import add_case_note
from fraud_detection.tools.update_case_status import update_case_status

# Add investigation notes (max 400 chars)
add_case_note(
    case_id="case_001",
    note="Customer confirmed legitimate transaction."
)

# Update case status
update_case_status(
    case_id="case_001",
    new_status="CLEARED",
    reason="Customer verification successful"
)
```

### Get Merchant Risk

```python
from fraud_detection.tools.get_merchant_risk import get_merchant_risk

risk = get_merchant_risk(
    merchant_id="merchant_123",
    time_window_h=24
)

# Returns merchant-level risk metrics for the past 24 hours
```

---

## Available Tools

| Tool | Purpose | Use When |
|------|---------|----------|
| **flag_transaction** | Generate risk flags | Need to identify specific fraud indicators |
| **score_transaction** | ML-based risk scoring | Evaluating transaction risk |
| **get_customer_profile** | Customer history & patterns | Suspicious account activity detected |
| **get_recent_txns** | Recent transaction history | Understanding account patterns |
| **get_device_assoc** | Device linkage & associations | Device mismatch or new device usage |
| **get_linked_accounts** | Connected/linked accounts | Detecting account rings or networks |
| **get_ip_intelligence** | IP geolocation & datacenter info | Geographic anomalies detected |
| **get_merchant_onboarding** | Merchant info & onboarding status | New or suspicious merchant |
| **get_merchant_risk** | Merchant-level risk metrics | Recurring merchant issues |
| **get_similar_fraud_cases** | Similar historical cases | Pattern matching & precedent lookup |
| **add_case_note** | Add investigation notes | Documenting investigation steps |
| **update_case_status** | Update case status | Closing or escalating cases |
| **submit_false_positive_feedback** | Report false positives | Improving model accuracy |

---

## Configuration

### Risk Thresholds (`config.py`)

```python
TRIAGE_THRESHOLD = 0.25      # CLEARED vs FLAGGED at Stage 1
BAND_LOW    = 0.30           # Low risk (minimal investigation)
BAND_MEDIUM = 0.60           # Medium risk (profile + merchant check)
BAND_HIGH   = 0.80           # High risk (full investigation)
                             # >= 0.80 → CRITICAL (block and escalate)
```

### Disposable Email Domains

Over 50+ common disposable email providers are pre-configured. Add custom domains in `config.py`:

```python
DISPOSABLE = ['domain1', 'domain2', ...]
```

### Merchant Recurrence

```python
MERCHANT_RECURRENCE_THRESHOLD = 3   # CRITICAL flags before escalation
MERCHANT_RECURRENCE_WINDOW_H = 24   # Rolling window (hours)
```

---

## Development

### Project Structure

- **`server.py`** — MCP server main entry point
- **`fraud_detection/`** — Core fraud detection package
- **`tools/`** — Individual tool implementations
- **`db_setup.py`** — Database initialization
- **`fraud_dataset_v5_ml_ready.csv`** — Training/test data
- **`feature_columns.json`** — ML feature specification
- **`cat_encodings.json`** — Categorical encodings

### Adding New Tools

1. Create a new file in `fraud_detection/tools/`
2. Implement tool logic with clear input/output specification
3. Register tool in `server.py`
4. Add tool to routing engine in `tool_router.py` if needed

### Testing

```bash
# Run tests
pytest tests/

# Check code quality
flake8 fraud_detection/
```

---

## Key Features & Recent Improvements

✅ **IP Datacenter Detection** — Two-layer approach (ISP string match + CIDR prefix fallback)  
✅ **Case Note Hard Limit** — 400 character maximum, hard rejection enforced  
✅ **Frictionless Bypass Detection** — 3DS silent pass + disposable/new account flagged  
✅ **Merchant Recurrence Escalation** — Automatic flag when ≥3 CRITICAL flags in 24h  
✅ **Update Case Status Prerequisites** — Enforces `add_case_note` before status change  
✅ **Fallback Mechanisms** — `get_recent_txns` fallback when customer profile returns no data  
✅ **Velocity Per Merchant** — Per-merchant 5-min velocity feature for bot detection  
✅ **False Positive Feedback** — Validates `rule_triggered` against known rule names  

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Average Scoring Latency | < 200ms |
| Stage 1 Triage (no DB) | < 20ms |
| SHAP Explanation Generation | < 50ms |
| Model Accuracy | 94.2% (validation set) |
| Investigation Cost | 0.12–0.45 (normalized) |

---

## Documentation

- [Complete Workflow & Updates](COMPLETE_WORKFLOW_AND_UPDATES.md) — Detailed implementation notes
- [Refactoring Summary](REFACTORING_SUMMARY.md) — Architectural changes
- [Migration Notes](MIGRATION_TO_ROOT_SERVER.md) — Server migration details

---

## Support & Contribution

For issues, feature requests, or contributions, please refer to the main repository:  
[Agentic_FRM — GitHub](https://github.com/Santpal1/Agentic_FRM)

---

**Last Updated**: April 21, 2026  
**Version**: 1.0  
**Status**: Production Ready
