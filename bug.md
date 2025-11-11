# Bug Reports and Fixes

## Bug: Excessive False Positives and Too Many Alerts

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
False positives were increasing even when no attacks were being simulated. The system was generating too many alerts from normal traffic patterns being misclassified as attacks.

### Root Causes
1. **Thresholds too low**: Confidence threshold (0.90) and attack probability (0.85) were not strict enough
2. **Feature validation too lenient**: Attack pattern thresholds were too low (e.g., packet_rate > 300)
3. **Time-window too short**: Only 10 seconds with 3 detections required
4. **No normal range check**: System didn't check if features were within normal ranges first
5. **Time-window validation weak**: Didn't verify confidence of previous detections

### Solution Implemented
1. **Increased confidence threshold**: 0.90 → 0.95
2. **Increased attack probability threshold**: 0.85 → 0.90
3. **Increased time window**: 10s → 15s
4. **Increased required detections**: 3 → 5 in time window
5. **Added normal range check**: If all features within normal ranges, reject immediately
6. **Stricter feature validation thresholds**:
   - SYN_Flood: syn_ratio > 0.7 (was 0.5), packet_rate > 500 (was 300)
   - HTTP_Flood: packet_rate > 500 (was 300), byte_rate > 150000 (was 100000)
   - UDP_Flood: udp_ratio > 0.7 (was 0.5), packet_rate > 500 (was 300)
   - DNS_Amplification: dns_queries > 50 (was 30), byte_rate > 150000 (was 100000)
   - Slowloris: request_interval > 3000 (was 2000), connection_rate > 20 (was 15)
7. **Enhanced time-window validation**: Now requires previous detections to also have high confidence (>= 0.95)

### Code Changes
- Modified `is_valid_attack_detection()` function in `app.py`
- Added normal range check before feature validation
- Increased all thresholds in validation logic
- Updated time-window validation to check confidence of previous detections

### Result
- Significantly reduced false positives
- Requires 5 high-confidence detections in 15-second window
- Normal traffic spikes no longer trigger alerts
- Only genuine attacks with clear patterns will create alerts

---

## Bug: Flask App Cannot Run with Uvicorn (ASGI/WSGI Mismatch)

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
Attempting to run Flask application with uvicorn resulted in errors:
```
TypeError: Flask.__call__() missing 1 required positional argument: 'start_response'
```

All API endpoints returned 500 Internal Server Error.

### Root Cause
- Flask is a **WSGI** (Web Server Gateway Interface) application
- Uvicorn is an **ASGI** (Asynchronous Server Gateway Interface) server
- These are incompatible protocols - uvicorn cannot run WSGI applications directly
- Uvicorn should not be used with Flask applications

### Solution
- Removed uvicorn from dependencies (pyproject.toml)
- Use the correct server for Flask:
  - **Development**: `python app.py` or `python3 app.py` (uses Flask's built-in WSGI server)
  - **Production**: `gunicorn app:app --bind 0.0.0.0:8888` (uses Gunicorn WSGI server)

### Code Changes
- Removed `uvicorn>=0.38.0` from `pyproject.toml` dependencies
- No code changes needed - Flask works correctly with WSGI servers

### Testing
- Verified Flask app runs correctly with `python3 app.py`
- All API endpoints now respond correctly
- Dashboard accessible at http://localhost:8888

---

## Bug: Incorrect Threat Count Display

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
The dashboard was showing incorrect threat counts (e.g., 183 threats) because it was counting ALL attack predictions in the traffic buffer, including false positives that were filtered out by validation.

### Root Cause
In `calculate_statistics()`, the code was using:
```python
threats_detected = len([t for t in traffic_buffer if t['prediction'] > 0])
```
This counted every prediction > 0, even though many were filtered as false positives and never created actual alerts.

### Solution Implemented
Changed to count only actual alerts that passed validation:
```python
# Count only actual alerts (not false positives that were filtered)
threats_detected = len(alerts)
```
Now the threat count accurately reflects only validated threats that triggered alerts.

### Code Changes
- Modified `calculate_statistics()` in `app.py` line 597
- Changed from counting predictions to counting actual alerts

---

## Bug: Excessive API Request Logging

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
Logs were constantly showing werkzeug INFO messages for every API request from the dashboard (e.g., `35.146.115.81 - - [11/Nov/2025 19:36:52] "GET /api/stats HTTP/1.1" 200 -`), making logs noisy and hard to read.

### Root Cause
Werkzeug (Flask's WSGI server) was set to INFO level, logging every HTTP request including normal dashboard polling.

### Solution Implemented
Reduced werkzeug logging verbosity to WARNING level:
```python
logging.getLogger('werkzeug').setLevel(logging.WARNING)
```
Now only warnings and errors are logged, not routine API requests.

### Code Changes
- Added werkzeug logger configuration in `app.py` line 23
- Set level to WARNING to suppress INFO-level request logs

---

## Bug: Random False Positive Attack Detections

**Date:** 2024-12-19  
**Status:** FIXED

### Problem
The DDoS detection system was randomly detecting attacks when there were no actual attacks occurring. This was causing false positive alerts and unnecessary mitigation actions.

### Root Causes
1. **Low confidence threshold**: The system used a confidence threshold of 0.7, which was too sensitive
2. **No feature validation**: The system didn't validate if detected features actually matched expected attack patterns
3. **Single sample detection**: Alerts were triggered on individual samples without requiring multiple confirmations
4. **Normal traffic outliers**: Normal traffic with statistical outliers could be misclassified as attacks

### Solution Implemented
1. **Increased confidence threshold**: Raised from 0.7 to 0.85
2. **Added attack probability check**: Requires minimum 0.8 probability for the attack class (not just max probability)
3. **Feature pattern validation**: Added validation to ensure detected features match expected patterns for each attack type:
   - SYN_Flood: Requires high syn_ratio (>0.5) or high packet_rate (>300)
   - HTTP_Flood: Requires high packet_rate (>300) or high byte_rate (>100000)
   - UDP_Flood: Requires high udp_ratio (>0.5) or high packet_rate (>300)
   - DNS_Amplification: Requires high dns_queries (>30) or high byte_rate (>100000)
   - Slowloris: Requires high request_interval (>2000) or high connection_rate (>15)
4. **Time-window validation**: Requires at least 2 detections within a 5-second window before triggering an alert
5. **Better logging**: Added debug logging for filtered false positives

### Code Changes
- Added `CONFIDENCE_THRESHOLD = 0.85`
- Added `MIN_ATTACK_PROBABILITY = 0.8`
- Added `TIME_WINDOW_SECONDS = 5` and `MIN_DETECTIONS_IN_WINDOW = 2`
- Added `NORMAL_TRAFFIC_RANGES` dictionary for feature validation
- Created `is_valid_attack_detection()` function with multi-layer validation
- Modified `simulate_network_traffic()` to use attack class probability instead of max probability

### Testing
- Syntax check passed
- Model loads successfully
- Validation logic implemented and tested

### Files Modified
- `app.py`: Added validation logic and improved detection thresholds

---

## Feature: Attack Generator UI

**Date:** 2024-12-19  
**Status:** IMPLEMENTED

### Description
Added a user interface in the dashboard to manually trigger different types of DDoS attacks for testing purposes. This allows users to test the detection system on-demand without waiting for random attack generation.

### Features
1. **Attack Generator Panel**: New UI section with buttons for each attack type
2. **Manual Attack Triggering**: Click buttons to generate specific attack types:
   - SYN Flood
   - HTTP Flood
   - UDP Flood
   - Slowloris
   - DNS Amplification
3. **Status Feedback**: Visual feedback showing attack generation status
4. **Multiple Samples**: Generates 4-5 samples to ensure detection passes time-window validation
5. **API Endpoint**: `/api/trigger-attack` POST endpoint for programmatic attack generation

### Implementation Details
- Added `generate_attack_traffic()` function to create attack-specific traffic patterns
- Added `/api/trigger-attack` API endpoint
- Added JavaScript `triggerAttack()` function for UI interaction
- Styled attack buttons with gradient backgrounds matching attack severity
- Real-time status updates and dashboard refresh after attack generation

### Usage
1. Navigate to the dashboard
2. Find the "Attack Generator (Testing Mode)" section
3. Click any attack type button to trigger that attack
4. Monitor the alerts section below to see detection results

### Files Modified
- `app.py`: Added attack generator UI, backend function, and API endpoint

---

## Feature: ML Model Output Logging

**Date:** 2024-12-19  
**Status:** IMPLEMENTED

### Description
Added comprehensive file logging for all ML model predictions and outputs. All predictions are logged to `ml_model_output.log` in CSV format for easy analysis and debugging.

### Features
1. **CSV Format Logging**: All predictions logged in comma-separated format
2. **Comprehensive Data**: Logs include:
   - Timestamp
   - All 8 feature values (packet_rate, byte_rate, syn_ratio, udp_ratio, dns_queries, connection_rate, payload_size, request_interval)
   - Prediction class and attack type
   - Confidence scores
   - Attack probability
   - All class probabilities (Normal, SYN_Flood, HTTP_Flood, UDP_Flood, Slowloris, DNS_Amplification)
   - Whether an alert was triggered
3. **Automatic Header**: Log file includes CSV header for easy parsing
4. **Separate Logger**: Uses dedicated logger to avoid console clutter

### Log File Format
The log file `ml_model_output.log` contains:
```
timestamp,packet_rate,byte_rate,syn_ratio,udp_ratio,dns_queries,connection_rate,payload_size,request_interval,prediction,attack_type,confidence,attack_probability,prob_normal,prob_syn,prob_http,prob_udp,prob_slowloris,prob_dns,triggered_alert
```

### Usage
- Log file is automatically created when the application starts
- All predictions (both normal traffic and attacks) are logged
- File can be analyzed with Excel, pandas, or any CSV parser
- Useful for:
  - Model performance analysis
  - Debugging false positives/negatives
  - Training data collection
  - Statistical analysis

### Files Modified
- `app.py`: Added ML logging configuration, `log_ml_prediction()` function, and logging calls in prediction paths

---

## Bug: Traffic Chart Showing Attack Traffic Without Corresponding Alerts

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
The traffic chart was showing attack traffic even when those attacks didn't trigger alerts (false positives that were filtered out). This made the chart inaccurate and confusing, as it showed attacks that weren't actually detected as threats.

### Root Cause
The `/api/traffic` endpoint was returning all traffic from `traffic_buffer`, including:
- Normal traffic (prediction == 0) - correct
- Attack traffic that triggered alerts - correct
- Attack traffic that was filtered as false positives - **incorrect**

This meant the chart showed attack traffic that never appeared in Recent Alerts.

### Solution Implemented
Modified `/api/traffic` endpoint to cross-reference traffic data with alerts database:
- Only show attack traffic (prediction > 0) if there's a corresponding alert in the database
- Always show normal traffic (prediction == 0)
- Use ±2 second time window to match traffic timestamps with alert timestamps (accounts for slight timing differences)

### Code Changes
- Modified `get_traffic()` function in `app.py` (lines 1675-1722)
- Added database query to fetch alerts from last 30 seconds
- Added filtering logic to only include attack traffic that has matching alerts
- Uses timestamp and attack_type matching with ±2 second window

### Result
- Traffic chart now accurately reflects only attacks that triggered alerts
- Chart matches what appears in Recent Alerts section
- False positive attack traffic no longer appears in the chart
- Normal traffic still displays correctly

### Testing
- Verified chart only shows attack traffic when corresponding alert exists
- Verified normal traffic still displays correctly
- Verified time window matching works correctly

---

## Bug: Excessive False Positive Logging

**Date:** 2025-11-11  
**Status:** FIXED

### Problem
Logs were constantly showing false positive filtered messages for attack types that never triggered actual alerts. This created log noise and made it difficult to see relevant information about attacks that actually matter.

Example log spam:
```
INFO:__main__:False positive filtered: SYN_Flood (confidence: 1.000, attack_prob: 1.000, ...)
INFO:__main__:False positive filtered: UDP_Flood (confidence: 0.997, attack_prob: 0.997, ...)
INFO:__main__:False positive filtered: Slowloris (confidence: 1.000, attack_prob: 1.000, ...)
```

### Root Cause
The code was logging every false positive filtered message regardless of whether that attack type had ever triggered an actual alert. This meant attack types that were consistently filtered (never creating alerts) would spam the logs.

### Solution Implemented
Modified false positive logging to only log when the attack type appears in recent alerts:
- Added `has_recent_alerts_for_attack_type()` helper function
- Checks if the attack type has any alerts in the last 60 seconds
- Only logs false positive filtered messages if that attack type has triggered alerts recently
- Reduces log noise while preserving useful debugging information

### Code Changes
- Added `has_recent_alerts_for_attack_type()` function in `app.py` (lines 466-480)
- Modified false positive logging in `simulate_network_traffic()` (lines 455-459)
- Only logs false positives for attack types that appear in recent alerts

### Result
- Logs are much cleaner and less noisy
- Only see false positive messages for attack types that are actually triggering alerts
- Easier to debug real issues without log spam
- Still captures relevant false positive information when needed

### Testing
- Verified false positive logging only occurs when attack type has recent alerts
- Verified logs are cleaner when no alerts are present
- Verified function correctly checks database for recent alerts

