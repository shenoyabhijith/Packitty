# Bug Reports and Fixes

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

