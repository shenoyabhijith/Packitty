from flask import Flask, render_template_string, jsonify, request
import numpy as np
import joblib
import time
from collections import deque
import threading
import json
import subprocess
import logging
from datetime import datetime
import random
import os
import sqlite3
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom filter to suppress 400 Bad Request errors from scanners/bots
class SuppressBadRequestFilter(logging.Filter):
    def filter(self, record):
        # Suppress werkzeug 400 errors (malformed requests from scanners)
        if 'werkzeug' in record.name:
            if 'code 400' in str(record.getMessage()) or 'Bad request' in str(record.getMessage()):
                return False
        return True

# Apply filter to werkzeug logger
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(SuppressBadRequestFilter())
werkzeug_logger.setLevel(logging.ERROR)  # Only log errors, suppress warnings and 400 bad requests

# Import AI Agent module
try:
    from ai_agent import get_ai_agent
    AI_AGENT_AVAILABLE = True
except ImportError:
    AI_AGENT_AVAILABLE = False
    logger.warning("AI agent module not available")

# Configure ML model output logging to file
ml_logger = logging.getLogger('ml_model')
ml_logger.setLevel(logging.INFO)
# Prevent duplicate logs in console
ml_logger.propagate = False

# Create file handler for ML model logs
ml_file_handler = logging.FileHandler('ml_model_output.log')
ml_file_handler.setLevel(logging.INFO)

# Create formatter for ML logs (CSV-like format for easy parsing)
ml_formatter = logging.Formatter(
    '%(asctime)s,%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
ml_file_handler.setFormatter(ml_formatter)
ml_logger.addHandler(ml_file_handler)

# Write header to log file (only if file is new/empty)
def initialize_ml_log_file():
    """Write CSV header to ML log file if it doesn't exist or is empty"""
    import os
    log_file = 'ml_model_output.log'
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        header = (
            'timestamp,packet_rate,byte_rate,syn_ratio,udp_ratio,dns_queries,connection_rate,'
            'payload_size,request_interval,prediction,attack_type,confidence,attack_probability,'
            'prob_normal,prob_syn,prob_http,prob_udp,prob_slowloris,prob_dns,triggered_alert\n'
        )
        with open(log_file, 'w') as f:
            f.write(header)

app = Flask(__name__)

# Suppress 400 Bad Request errors from malformed requests (scanners/bots)
@app.errorhandler(400)
def handle_bad_request(e):
    """Silently handle 400 Bad Request errors to reduce log noise from scanners"""
    return '', 400

# Database configuration
DB_PATH = os.getenv('DB_PATH', 'packitty.db')

def init_database():
    """Initialize SQLite database with alerts and mitigation_history tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            attack_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            packet_rate REAL,
            byte_rate REAL,
            connection_rate REAL,
            status TEXT NOT NULL,
            mitigation_action TEXT,
            ai_powered INTEGER DEFAULT 0,
            ai_reasoning TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create mitigation_history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mitigation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            alert_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            command TEXT,
            status TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            reasoning TEXT,
            ai_powered INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # Create stats table to track total requests
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize total_requests counter if it doesn't exist
    cursor.execute('''
        INSERT OR IGNORE INTO stats (key, value) 
        VALUES ('total_requests', 0)
    ''')
    
    # Create indexes for better query performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mitigation_alert_id ON mitigation_history(alert_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mitigation_timestamp ON mitigation_history(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mitigation_action ON mitigation_history(action)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mitigation_status ON mitigation_history(status)')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_PATH}")

# Initialize database on startup
init_database()

# Load the trained model
try:
    model = joblib.load('ddos_model.pkl')
    feature_names = joblib.load('feature_names.pkl')
    logger.info("ML model loaded successfully")
except:
    logger.error("Model not found. Please run train_model.py first.")
    exit(1)

# Global data structures for real-time monitoring
traffic_buffer = deque(maxlen=1000)
# Note: blocked_ips and total_requests_count are now tracked in database

# Detection thresholds and validation
CONFIDENCE_THRESHOLD = 0.95  # Increased to 0.95 to reduce false positives
MIN_ATTACK_PROBABILITY = 0.90  # Minimum probability for attack class (increased to 0.90)
TIME_WINDOW_SECONDS = 15  # Time window for multiple detections (increased to 15 seconds)
MIN_DETECTIONS_IN_WINDOW = 5  # Require at least 5 detections in time window (increased)

# Test mode: Set to True to generate only normal traffic (no attacks) for testing false positives
TEST_MODE_NORMAL_ONLY = False  # Set to False to enable attack simulation

# Normal traffic feature ranges (to filter outliers)
NORMAL_TRAFFIC_RANGES = {
    'packet_rate': (0, 300),  # packets per second
    'byte_rate': (0, 100000),  # bytes per second
    'syn_ratio': (0, 0.5),  # SYN packet ratio
    'udp_ratio': (0, 0.5),  # UDP packet ratio
    'dns_queries': (0, 30),  # DNS queries per second
    'connection_rate': (0, 15),  # connections per second
    'payload_size': (0, 1000),  # average payload size
    'request_interval': (0, 2000)  # average request interval in ms
}

# Attack type mappings
ATTACK_TYPES = {
    0: 'Normal',
    1: 'SYN_Flood',
    2: 'HTTP_Flood', 
    3: 'UDP_Flood',
    4: 'Slowloris',
    5: 'DNS_Amplification'
}

def log_ml_prediction(features, prediction, probabilities, traffic_data, triggered_alert=False):
    """
    Log ML model prediction output to file
    Format: timestamp,packet_rate,byte_rate,syn_ratio,udp_ratio,dns_queries,connection_rate,payload_size,request_interval,
            prediction,attack_type,confidence,attack_probability,prob_normal,prob_syn,prob_http,prob_udp,prob_slowloris,prob_dns,triggered_alert
    """
    feature_names_list = ['packet_rate', 'byte_rate', 'syn_ratio', 'udp_ratio', 
                         'dns_queries', 'connection_rate', 'payload_size', 'request_interval']
    
    # Format features as comma-separated values
    features_str = ','.join([f'{f:.4f}' for f in features])
    
    # Get all class probabilities
    prob_normal = probabilities[0] if len(probabilities) > 0 else 0.0
    prob_syn = probabilities[1] if len(probabilities) > 1 else 0.0
    prob_http = probabilities[2] if len(probabilities) > 2 else 0.0
    prob_udp = probabilities[3] if len(probabilities) > 3 else 0.0
    prob_slowloris = probabilities[4] if len(probabilities) > 4 else 0.0
    prob_dns = probabilities[5] if len(probabilities) > 5 else 0.0
    
    # Create log message
    log_message = (
        f'{features_str},'
        f'{prediction},{ATTACK_TYPES[prediction]},'
        f'{traffic_data["confidence"]:.4f},{traffic_data.get("attack_probability", 0.0):.4f},'
        f'{prob_normal:.4f},{prob_syn:.4f},{prob_http:.4f},{prob_udp:.4f},{prob_slowloris:.4f},{prob_dns:.4f},'
        f'{1 if triggered_alert else 0}'
    )
    
    ml_logger.info(log_message)

# Severity levels
SEVERITY_LEVELS = {
    'SYN_Flood': 'HIGH',
    'HTTP_Flood': 'HIGH',
    'UDP_Flood': 'MEDIUM',
    'Slowloris': 'MEDIUM',
    'DNS_Amplification': 'HIGH'
}

def generate_private_ip():
    """
    Generate a random private IP address
    Returns IP from private ranges: 10.x.x.x, 172.16-31.x.x, or 192.168.x.x
    """
    ip_type = random.choice(['10', '172', '192'])
    
    if ip_type == '10':
        # 10.0.0.0/8
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    elif ip_type == '172':
        # 172.16.0.0/12
        return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # 192.168.0.0/16
        return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_attack_traffic(attack_type_name):
    """
    Generate traffic for a specific attack type
    Returns the generated features
    """
    attack_type_map = {
        'SYN_Flood': 1,
        'HTTP_Flood': 2,
        'UDP_Flood': 3,
        'Slowloris': 4,
        'DNS_Amplification': 5
    }
    
    traffic_type = attack_type_map.get(attack_type_name, 0)
    
    if traffic_type == 1:  # SYN Flood
        features = np.random.normal(
            [1000, 80000, 0.9, 0.1, 5, 50, 100, 100],
            [200, 15000, 0.05, 0.05, 2, 10, 50, 50]
        )
    elif traffic_type == 2:  # HTTP Flood
        features = np.random.normal(
            [800, 120000, 0.2, 0.1, 15, 20, 400, 200],
            [150, 20000, 0.1, 0.05, 5, 5, 100, 100]
        )
    elif traffic_type == 3:  # UDP Flood
        features = np.random.normal(
            [1200, 100000, 0.1, 0.8, 8, 30, 300, 150],
            [250, 18000, 0.05, 0.1, 3, 8, 80, 80]
        )
    elif traffic_type == 4:  # Slowloris
        features = np.random.normal(
            [200, 30000, 0.3, 0.2, 12, 100, 50, 5000],
            [50, 8000, 0.1, 0.1, 4, 20, 20, 1000]
        )
    elif traffic_type == 5:  # DNS Amplification
        features = np.random.normal(
            [600, 150000, 0.1, 0.6, 50, 15, 800, 300],
            [120, 25000, 0.05, 0.1, 10, 5, 200, 150]
        )
    else:
        # Default to normal traffic if attack type not found
        features = np.random.normal(
            [100, 50000, 0.1, 0.2, 10, 5, 500, 1000],
            [20, 10000, 0.05, 0.1, 5, 2, 200, 500]
        )
    
    features = np.abs(features)
    
    # Make prediction
    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]
    max_confidence = max(probabilities)
    attack_probability = probabilities[prediction] if prediction > 0 else 0
    
    # Log traffic data
    traffic_data = {
        'timestamp': time.time(),
        'features': features.tolist(),
        'prediction': int(prediction),
        'confidence': float(max_confidence),
        'attack_probability': float(attack_probability),
        'attack_type': ATTACK_TYPES[prediction]
    }
    
    traffic_buffer.append(traffic_data)
    # Update total requests counter in database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE stats SET value = value + 1, updated_at = CURRENT_TIMESTAMP 
        WHERE key = 'total_requests'
    ''')
    conn.commit()
    conn.close()
    
    # Log first prediction
    triggered_alert_first = False
    if prediction > 0:
        if is_valid_attack_detection(traffic_data, features, attack_probability):
            create_alert(traffic_data, features)
            triggered_alert_first = True
    
    log_ml_prediction(features, prediction, probabilities, traffic_data, triggered_alert_first)
    
    # Generate multiple samples to ensure detection (bypass validation for manual triggers)
    # Generate 3-5 samples to ensure it passes time-window validation
    for _ in range(4):
        time.sleep(0.1)  # Small delay between samples
        # Generate similar but slightly varied features
        features_variation = features + np.random.normal(0, features * 0.05)
        features_variation = np.abs(features_variation)
        
        prediction_var = model.predict([features_variation])[0]
        probabilities_var = model.predict_proba([features_variation])[0]
        max_confidence_var = max(probabilities_var)
        attack_probability_var = probabilities_var[prediction_var] if prediction_var > 0 else 0
        
        traffic_data_var = {
            'timestamp': time.time(),
            'features': features_variation.tolist(),
            'prediction': int(prediction_var),
            'confidence': float(max_confidence_var),
            'attack_probability': float(attack_probability_var),
            'attack_type': ATTACK_TYPES[prediction_var]
        }
        
        traffic_buffer.append(traffic_data_var)
        # Update total requests counter in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE stats SET value = value + 1, updated_at = CURRENT_TIMESTAMP 
            WHERE key = 'total_requests'
        ''')
        conn.commit()
        conn.close()
        
        # Trigger alert if validation passes
        triggered_alert_var = False
        if prediction_var > 0:
            if is_valid_attack_detection(traffic_data_var, features_variation, attack_probability_var):
                create_alert(traffic_data_var, features_variation)
                triggered_alert_var = True
        
        # Log each variation prediction
        log_ml_prediction(features_variation, prediction_var, probabilities_var, traffic_data_var, triggered_alert_var)
    
    return traffic_data

def simulate_network_traffic():
    """
    Simulate network traffic with realistic patterns
    In production, this would parse real network data from tcpdump/scapy
    """
    while True:
        # Generate realistic traffic features
        # In test mode, generate only normal traffic to verify false positive elimination
        if TEST_MODE_NORMAL_ONLY:
            traffic_type = 0  # Only normal traffic
        else:
            traffic_type = np.random.choice([0, 1, 2, 3, 4, 5], p=[0.7, 0.06, 0.06, 0.06, 0.06, 0.06])
        
        if traffic_type == 0:  # Normal traffic
            features = np.random.normal(
                [100, 50000, 0.1, 0.2, 10, 5, 500, 1000],
                [20, 10000, 0.05, 0.1, 5, 2, 200, 500]
            )
        elif traffic_type == 1:  # SYN Flood
            features = np.random.normal(
                [1000, 80000, 0.9, 0.1, 5, 50, 100, 100],
                [200, 15000, 0.05, 0.05, 2, 10, 50, 50]
            )
        elif traffic_type == 2:  # HTTP Flood
            features = np.random.normal(
                [800, 120000, 0.2, 0.1, 15, 20, 400, 200],
                [150, 20000, 0.1, 0.05, 5, 5, 100, 100]
            )
        elif traffic_type == 3:  # UDP Flood
            features = np.random.normal(
                [1200, 100000, 0.1, 0.8, 8, 30, 300, 150],
                [250, 18000, 0.05, 0.1, 3, 8, 80, 80]
            )
        elif traffic_type == 4:  # Slowloris
            features = np.random.normal(
                [200, 30000, 0.3, 0.2, 12, 100, 50, 5000],
                [50, 8000, 0.1, 0.1, 4, 20, 20, 1000]
            )
        else:  # DNS Amplification
            features = np.random.normal(
                [600, 150000, 0.1, 0.6, 50, 15, 800, 300],
                [120, 25000, 0.05, 0.1, 10, 5, 200, 150]
            )
        
        features = np.abs(features)
        
        # Make prediction
        prediction = model.predict([features])[0]
        probabilities = model.predict_proba([features])[0]
        max_confidence = max(probabilities)
        attack_probability = probabilities[prediction] if prediction > 0 else 0
        
        # Log traffic data
        traffic_data = {
            'timestamp': time.time(),
            'features': features.tolist(),
            'prediction': int(prediction),
            'confidence': float(max_confidence),
            'attack_probability': float(attack_probability),
            'attack_type': ATTACK_TYPES[prediction]
        }
        
        traffic_buffer.append(traffic_data)
        # Update total requests counter in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE stats SET value = value + 1, updated_at = CURRENT_TIMESTAMP 
            WHERE key = 'total_requests'
        ''')
        conn.commit()
        conn.close()
        
        # Validate if this is truly an attack (not a false positive)
        triggered_alert = False
        if prediction > 0:
            if is_valid_attack_detection(traffic_data, features, attack_probability):
                create_alert(traffic_data, features)
                triggered_alert = True
            else:
                # Only log false positive if this attack type appears in recent alerts
                if has_recent_alerts_for_attack_type(ATTACK_TYPES[prediction]):
                    logger.info(f"False positive filtered: {ATTACK_TYPES[prediction]} "
                               f"(confidence: {max_confidence:.3f}, attack_prob: {attack_probability:.3f}, "
                               f"features: packet_rate={features[0]:.1f}, udp_ratio={features[3]:.3f})")
        
        # Log ML model output to file
        log_ml_prediction(features, prediction, probabilities, traffic_data, triggered_alert)
        
        time.sleep(1)  # Simulate 1 second intervals

def has_recent_alerts_for_attack_type(attack_type, time_window=60):
    """Check if there are any recent alerts for the given attack type (within last 60 seconds)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    current_time = time.time()
    time_threshold = current_time - time_window
    
    cursor.execute('''
        SELECT COUNT(*) FROM alerts 
        WHERE attack_type = ? AND timestamp >= ?
    ''', (attack_type, time_threshold))
    
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def is_valid_attack_detection(traffic_data, features, attack_probability):
    """
    Validate if an attack detection is legitimate (not a false positive)
    Returns True if the detection should trigger an alert
    """
    # Check 1: Attack probability must be high enough
    if attack_probability < MIN_ATTACK_PROBABILITY:
        return False
    
    # Check 2: Overall confidence must exceed threshold
    if traffic_data['confidence'] < CONFIDENCE_THRESHOLD:
        return False
    
    # Check 3: First check if features are within normal ranges - if so, definitely false positive
    packet_rate, byte_rate, syn_ratio, udp_ratio, dns_queries, connection_rate, payload_size, request_interval = features
    
    # If all features are within normal ranges, it's definitely a false positive
    if (packet_rate <= NORMAL_TRAFFIC_RANGES['packet_rate'][1] and
        byte_rate <= NORMAL_TRAFFIC_RANGES['byte_rate'][1] and
        syn_ratio <= NORMAL_TRAFFIC_RANGES['syn_ratio'][1] and
        udp_ratio <= NORMAL_TRAFFIC_RANGES['udp_ratio'][1] and
        dns_queries <= NORMAL_TRAFFIC_RANGES['dns_queries'][1] and
        connection_rate <= NORMAL_TRAFFIC_RANGES['connection_rate'][1] and
        payload_size <= NORMAL_TRAFFIC_RANGES['payload_size'][1] and
        request_interval <= NORMAL_TRAFFIC_RANGES['request_interval'][1]):
        return False
    
    # Check 4: Feature validation - ensure features match expected attack patterns
    # If model predicts an attack but features don't match, it's likely a false positive
    feature_names_list = ['packet_rate', 'byte_rate', 'syn_ratio', 'udp_ratio', 
                         'dns_queries', 'connection_rate', 'payload_size', 'request_interval']
    
    attack_type = traffic_data['attack_type']
    features_match_attack = False
    
    # Check if features match what we'd expect for this attack type (stricter thresholds)
    for i, feature_name in enumerate(feature_names_list):
        feature_value = features[i]
        
        # For each attack type, check if key features match expected patterns (with stricter thresholds)
        if attack_type == 'SYN_Flood':
            if feature_name == 'syn_ratio' and feature_value > 0.7:  # Increased from 0.5
                features_match_attack = True
            if feature_name == 'packet_rate' and feature_value > 500:  # Increased from 300
                features_match_attack = True
        elif attack_type == 'HTTP_Flood':
            if feature_name == 'packet_rate' and feature_value > 500:  # Increased from 300
                features_match_attack = True
            if feature_name == 'byte_rate' and feature_value > 150000:  # Increased from 100000
                features_match_attack = True
        elif attack_type == 'UDP_Flood':
            if feature_name == 'udp_ratio' and feature_value > 0.7:  # Increased from 0.5
                features_match_attack = True
            if feature_name == 'packet_rate' and feature_value > 500:  # Increased from 300
                features_match_attack = True
        elif attack_type == 'DNS_Amplification':
            if feature_name == 'dns_queries' and feature_value > 50:  # Increased from 30
                features_match_attack = True
            if feature_name == 'byte_rate' and feature_value > 150000:  # Increased from 100000
                features_match_attack = True
        elif attack_type == 'Slowloris':
            if feature_name == 'request_interval' and feature_value > 3000:  # Increased from 2000
                features_match_attack = True
            if feature_name == 'connection_rate' and feature_value > 20:  # Increased from 15
                features_match_attack = True
    
    # If features don't match expected attack patterns, it's likely a false positive
    if not features_match_attack:
        return False
    
    # Check 5: Time-window validation - require multiple detections
    current_time = traffic_data['timestamp']
    # Count previous detections (excluding current one) of the same attack type
    # Also check that they passed validation (have similar high confidence)
    recent_attacks = [
        t for t in traffic_buffer 
        if t['prediction'] == traffic_data['prediction'] 
        and t['timestamp'] < current_time  # Exclude current detection
        and (current_time - t['timestamp']) <= TIME_WINDOW_SECONDS
        and t.get('confidence', 0) >= CONFIDENCE_THRESHOLD  # Must also have high confidence
    ]
    
    # Require at least MIN_DETECTIONS_IN_WINDOW previous detections before alerting
    # This ensures we have multiple confirmations, not just one
    if len(recent_attacks) < MIN_DETECTIONS_IN_WINDOW:
        logger.debug(f"Time-window validation failed: Only {len(recent_attacks)} previous detections "
                    f"(need {MIN_DETECTIONS_IN_WINDOW}) for {attack_type}")
        return False
    
    # All validations passed
    return True

def create_alert(traffic_data, features):
    """Create alert for detected attack and trigger mitigation"""
    attack_type = traffic_data['attack_type']
    severity = SEVERITY_LEVELS.get(attack_type, 'MEDIUM')
    
    # Generate random private IP address
    source_ip = generate_private_ip()
    
    # Insert alert into database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO alerts (timestamp, attack_type, source_ip, severity, confidence,
                           packet_rate, byte_rate, connection_rate, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        traffic_data['timestamp'],
        attack_type,
        source_ip,
        severity,
        traffic_data['confidence'],
        features[0],  # packet_rate
        features[1],  # byte_rate
        features[5],  # connection_rate
        'DETECTED'
    ))
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create alert dict for immediate use
    alert = {
        'id': alert_id,
        'timestamp': traffic_data['timestamp'],
        'attack_type': attack_type,
        'source_ip': source_ip,
        'severity': severity,
        'confidence': traffic_data['confidence'],
        'features': {
            'packet_rate': features[0],
            'byte_rate': features[1],
            'connection_rate': features[5]
        },
        'status': 'DETECTED',
        'mitigation_action': None
    }
    
    logger.warning(f"ALERT: {attack_type} detected from {source_ip} (confidence: {traffic_data['confidence']:.3f})")
    
    # Trigger mitigation
    mitigation_result = execute_mitigation(alert)
    
    # Update alert in database with mitigation info
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE alerts 
        SET mitigation_action = ?, status = ?, ai_powered = ?, ai_reasoning = ?
        WHERE id = ?
    ''', (
        mitigation_result['action'],
        mitigation_result['status'],
        1 if mitigation_result.get('ai_powered', False) else 0,
        mitigation_result.get('reasoning', ''),
        alert_id
    ))
    conn.commit()
    conn.close()
    
    alert['mitigation_action'] = mitigation_result['action']
    alert['status'] = mitigation_result['status']
    alert['ai_powered'] = mitigation_result.get('ai_powered', False)
    alert['ai_reasoning'] = mitigation_result.get('reasoning', '')

def execute_mitigation(alert):
    """
    Execute mitigation using AI agent for intelligent decision making
    Falls back to rule-based logic if AI agent is not available
    """
    attack_type = alert['attack_type']
    source_ip = alert['source_ip']
    severity = alert['severity']
    
    # Get recent alerts for context from database
    current_time = time.time()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM alerts 
        WHERE timestamp >= ? 
        ORDER BY timestamp DESC
    ''', (current_time - 300,))  # Last 5 minutes
    recent_alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Get system statistics
    system_stats = calculate_statistics()
    
    # Use AI agent for intelligent decision making
    use_ai = os.getenv('USE_AI_AGENT', 'true').lower() == 'true' and AI_AGENT_AVAILABLE
    recommendation = None
    
    if use_ai:
        try:
            ai_agent = get_ai_agent(use_ai=True)
            recommendation = ai_agent.analyze_attack_context(alert, recent_alerts, system_stats)
            action = recommendation['action']
            reasoning = recommendation.get('reasoning', 'AI-based decision')
            
            logger.info(f"AI Agent Decision: {action} for {source_ip}")
            logger.info(f"AI Reasoning: {reasoning}")
            
            # Log AI decision explanation
            explanation = ai_agent.explain_decision(alert, recommendation)
            logger.info(f"AI Mitigation Explanation:\n{explanation}")
            
        except Exception as e:
            logger.error(f"AI agent error: {e}, falling back to rule-based")
            use_ai = False
            recommendation = None
    
    # Fallback to rule-based if AI not available or failed
    if not use_ai:
        if severity == 'HIGH' or attack_type in ['SYN_Flood', 'HTTP_Flood']:
            action = 'BLOCK'
            reasoning = f"Rule-based: High severity {attack_type} attack"
        else:
            action = 'RATE_LIMIT'
            reasoning = f"Rule-based: Moderate {attack_type} attack"
    
    # Execute UFW command if AI already executed it via tool calling
    tool_executed = recommendation.get('tool_executed', False) if recommendation else False
    
    if tool_executed:
        # AI already executed the UFW command via tool calling
        # Get the actual command from the recommendation if available
        actual_command = recommendation.get('ufw_command', f'sudo ufw {action.lower().replace("_", " ")} from {source_ip}')
        ufw_command = f"{actual_command} (EXECUTED via AI tool calling)"
        if action != 'MONITOR':
            status = 'MITIGATED'
        else:
            status = 'MONITORING'
    else:
        # Generate and execute firewall command
        from ufw_tools import block_ip_with_ufw, rate_limit_ip_with_ufw, ENABLE_UFW_EXECUTION
        
        if action == 'BLOCK':
            ufw_result = block_ip_with_ufw(source_ip)
            ufw_command = ufw_result.get('command', f'sudo ufw deny from {source_ip}')
            # Add execution status to command
            if ufw_result.get('simulated', False):
                ufw_command = f"{ufw_command} (SIMULATED - UFW execution disabled)"
            else:
                ufw_command = f"{ufw_command} (EXECUTED)"
            if ufw_result.get('success'):
                status = 'MITIGATED'
            else:
                status = 'FAILED'
        elif action == 'RATE_LIMIT':
            ufw_result = rate_limit_ip_with_ufw(source_ip)
            ufw_command = ufw_result.get('command', f'sudo ufw limit from {source_ip}')
            # Add execution status to command
            if ufw_result.get('simulated', False):
                ufw_command = f"{ufw_command} (SIMULATED - UFW execution disabled)"
            else:
                ufw_command = f"{ufw_command} (EXECUTED)"
            if ufw_result.get('success'):
                status = 'MITIGATED'
            else:
                status = 'FAILED'
        else:  # MONITOR
            ufw_command = f"# Monitor {source_ip} - no action taken"
            status = 'MONITORING'
    
    # Insert mitigation record into database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO mitigation_history 
        (timestamp, alert_id, action, command, status, source_ip, reasoning, ai_powered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        time.time(),
        alert['id'],
        action,
        ufw_command,
        status,
        source_ip,
        reasoning if use_ai else 'Rule-based decision',
        1 if use_ai else 0
    ))
    conn.commit()
    conn.close()
    
    mitigation_record = {
        'timestamp': time.time(),
        'alert_id': alert['id'],
        'action': action,
        'command': ufw_command,
        'status': status,
        'source_ip': source_ip,
        'reasoning': reasoning if use_ai else 'Rule-based decision',
        'ai_powered': use_ai
    }
    
    logger.info(f"MITIGATION: {action} executed for {source_ip} - Status: {status}")
    if use_ai:
        logger.info(f"AI Reasoning: {reasoning}")
    
    return {'action': action, 'status': status, 'reasoning': reasoning, 'ai_powered': use_ai}

def calculate_statistics():
    """Calculate real-time statistics - all from database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get total requests from stats table
    cursor.execute('SELECT value FROM stats WHERE key = ?', ('total_requests',))
    result = cursor.fetchone()
    total_requests = result[0] if result else 0
    
    # Count only actual alerts from database (not false positives that were filtered)
    cursor.execute('SELECT COUNT(*) FROM alerts')
    threats_detected = cursor.fetchone()[0]
    
    # Count blocked IPs from mitigation_history (distinct IPs with BLOCK action and MITIGATED status)
    cursor.execute('''
        SELECT COUNT(DISTINCT source_ip) FROM mitigation_history 
        WHERE action = 'BLOCK' AND status = 'MITIGATED'
    ''')
    blocked_ips_count = cursor.fetchone()[0]
    
    # Calculate AI-powered mitigations from database
    cursor.execute('SELECT COUNT(*) FROM mitigation_history WHERE ai_powered = 1')
    ai_mitigations = cursor.fetchone()[0]
    
    # Calculate attack distribution from database (only actual attacks, exclude Normal)
    cursor.execute('''
        SELECT attack_type, COUNT(*) as count FROM alerts 
        WHERE attack_type != 'Normal'
        GROUP BY attack_type
    ''')
    attack_dist = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Count total mitigations
    cursor.execute('SELECT COUNT(*) FROM mitigation_history')
    mitigation_rate = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_requests': total_requests,
        'threats_detected': threats_detected,
        'blocked_ips': blocked_ips_count,
        'mitigation_rate': mitigation_rate,
        'ai_mitigations': ai_mitigations,
        'attack_distribution': attack_dist,
        'uptime': time.time() - start_time
    }

# HTML template for the dashboard
dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDOS Shield - Real-time Detection & Mitigation</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            padding: 30px 0;
            background: rgba(30, 41, 59, 0.5);
            border-radius: 15px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
        }
        
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header p {
            font-size: 1.2em;
            color: #94a3b8;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(30, 41, 59, 0.8);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-value.high { color: #ef4444; }
        .stat-value.medium { color: #f59e0b; }
        .stat-value.low { color: #10b981; }
        .stat-value.info { color: #3b82f6; }
        
        .stat-label {
            color: #94a3b8;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-container {
            background: rgba(30, 41, 59, 0.8);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
        }
        
        .chart-container h3 {
            margin-bottom: 20px;
            color: #e2e8f0;
            font-size: 1.3em;
        }
        
        .alerts-section {
            background: rgba(30, 41, 59, 0.8);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            margin-bottom: 30px;
        }
        
        .alerts-section h3 {
            margin-bottom: 20px;
            color: #e2e8f0;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-item {
            background: rgba(15, 23, 42, 0.6);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 10px;
            border-left: 4px solid;
            transition: transform 0.2s ease;
        }
        
        .alert-item:hover {
            transform: translateX(5px);
        }
        
        .alert-HIGH { border-left-color: #ef4444; }
        .alert-MEDIUM { border-left-color: #f59e0b; }
        .alert-LOW { border-left-color: #10b981; }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .alert-type {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .alert-type.SYN_Flood { color: #ef4444; }
        .alert-type.HTTP_Flood { color: #dc2626; }
        .alert-type.UDP_Flood { color: #ea580c; }
        .alert-type.Slowloris { color: #d97706; }
        .alert-type.DNS_Amplification { color: #b91c1c; }
        
        .alert-time {
            color: #94a3b8;
            font-size: 0.9em;
        }
        
        .alert-details {
            color: #cbd5e1;
            font-size: 0.95em;
            line-height: 1.5;
        }
        
        .alert-action {
            margin-top: 10px;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .action-BLOCK {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .action-RATE_LIMIT {
            background: rgba(245, 158, 11, 0.2);
            color: #fcd34d;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .action-MONITOR {
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        
        .ai-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 10px;
            background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .ai-reasoning {
            margin-top: 10px;
            padding: 12px;
            background: rgba(139, 92, 246, 0.1);
            border-left: 3px solid #8b5cf6;
            border-radius: 5px;
            font-size: 0.9em;
            color: #cbd5e1;
            font-style: italic;
        }
        
        .ai-reasoning strong {
            color: #a78bfa;
            font-style: normal;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-MITIGATED { background: #10b981; }
        .status-DETECTED { background: #f59e0b; animation: pulse 2s infinite; }
        .status-FAILED { background: #ef4444; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .system-status {
            text-align: center;
            padding: 15px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 10px;
            margin-top: 20px;
        }
        
        .system-status.active {
            background: rgba(16, 185, 129, 0.1);
            border-color: rgba(16, 185, 129, 0.3);
            color: #10b981;
        }
        
        .attack-generator {
            background: rgba(30, 41, 59, 0.8);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            margin-bottom: 30px;
        }
        
        .attack-generator h3 {
            margin-bottom: 20px;
            color: #e2e8f0;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        
        .reset-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            font-size: 0.85em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(135deg, #64748b 0%, #475569 100%);
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .reset-btn:hover {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(239, 68, 68, 0.3);
        }
        
        .reset-btn:active {
            transform: translateY(0);
        }
        
        .attack-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .attack-btn {
            padding: 15px 20px;
            border: none;
            border-radius: 10px;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .attack-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
        }
        
        .attack-btn:active {
            transform: translateY(0);
        }
        
        .attack-btn.syn-flood {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        
        .attack-btn.http-flood {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            color: white;
        }
        
        .attack-btn.udp-flood {
            background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
            color: white;
        }
        
        .attack-btn.slowloris {
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
            color: white;
        }
        
        .attack-btn.dns-amplification {
            background: linear-gradient(135deg, #b91c1c 0%, #991b1b 100%);
            color: white;
        }
        
        .attack-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .attack-status {
            margin-top: 15px;
            padding: 10px;
            border-radius: 8px;
            text-align: center;
            font-size: 0.9em;
            display: none;
        }
        
        .attack-status.success {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
            display: block;
        }
        
        .attack-status.error {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
            display: block;
        }
        
        canvas {
            max-height: 300px;
        }
        
        @media (max-width: 768px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .container {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> DDOS Shield</h1>
            <p>Real-time ML-Powered Threat Detection & Automated Mitigation</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value info" id="total-requests">0</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high" id="threats-detected">0</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium" id="blocked-ips">0</div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low" id="mitigation-rate">0</div>
                <div class="stat-label">Mitigations</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="ai-mitigations" style="color: #8b5cf6;">0</div>
                <div class="stat-label"><i class="fas fa-robot"></i> AI-Powered</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3><i class="fas fa-chart-line"></i> Traffic Analysis</h3>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="chart-container">
                <h3><i class="fas fa-pie-chart"></i> Attack Distribution</h3>
                <canvas id="attackChart"></canvas>
            </div>
        </div>
        
        <div class="attack-generator">
            <h3>
                <span><i class="fas fa-bomb"></i> Attack Generator (Testing Mode)</span>
                <button class="reset-btn" onclick="resetStats()" title="Reset all dashboard stats">
                    <i class="fas fa-redo"></i> Reset
                </button>
            </h3>
            <p style="color: #94a3b8; margin-bottom: 15px;">Manually trigger attacks to test the detection system</p>
            <div class="attack-buttons">
                <button class="attack-btn syn-flood" onclick="triggerAttack('SYN_Flood')">
                    <i class="fas fa-bolt"></i> SYN Flood
                </button>
                <button class="attack-btn http-flood" onclick="triggerAttack('HTTP_Flood')">
                    <i class="fas fa-wave-square"></i> HTTP Flood
                </button>
                <button class="attack-btn udp-flood" onclick="triggerAttack('UDP_Flood')">
                    <i class="fas fa-water"></i> UDP Flood
                </button>
                <button class="attack-btn slowloris" onclick="triggerAttack('Slowloris')">
                    <i class="fas fa-hourglass-half"></i> Slowloris
                </button>
                <button class="attack-btn dns-amplification" onclick="triggerAttack('DNS_Amplification')">
                    <i class="fas fa-expand-arrows-alt"></i> DNS Amplification
                </button>
            </div>
            <div id="attack-status" class="attack-status"></div>
        </div>
        
        <div class="alerts-section">
            <h3><i class="fas fa-exclamation-triangle"></i> Recent Alerts</h3>
            <div id="alerts-container">
                <div style="text-align: center; padding: 40px; color: #94a3b8;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 2em; margin-bottom: 10px;"></i>
                    <p>Monitoring for threats...</p>
                </div>
            </div>
        </div>
        
        <div class="ai-agent-status" style="background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 10px; padding: 15px; margin-bottom: 20px;">
            <h3 style="color: #a78bfa; margin-bottom: 15px; display: flex; align-items: center; justify-content: center; gap: 10px;">
                <i class="fas fa-robot"></i> AI Agent Status
            </h3>
            <div id="ai-status-info" style="color: #cbd5e1; text-align: center; margin-bottom: 15px;">
                <span id="ai-status-text">Initializing...</span>
            </div>
            <div id="ai-decisions-container" style="margin-top: 15px;">
                <h4 style="color: #a78bfa; margin-bottom: 10px; font-size: 0.9em; text-align: center;">
                    <i class="fas fa-history"></i> Recent AI Decisions
                </h4>
                <div id="ai-decisions-list" style="max-height: 300px; overflow-y: auto;">
                    <div style="text-align: center; padding: 20px; color: #94a3b8; font-size: 0.9em;">
                        <i class="fas fa-clock"></i> Waiting for AI decisions...
                    </div>
                </div>
            </div>
        </div>
        
        <div class="system-status active">
            <i class="fas fa-check-circle"></i>
            <strong>System Status:</strong> Active & Monitoring
            <span id="uptime-display"></span>
        </div>
    </div>
    
    <script>
        // Chart configurations
        const chartColors = {
            primary: '#3b82f6',
            secondary: '#8b5cf6',
            success: '#10b981',
            warning: '#f59e0b',
            danger: '#ef4444',
            info: '#06b6d4'
        };
        
        // Initialize traffic chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Normal Traffic (Packets/sec)',
                    data: [],
                    borderColor: chartColors.success,
                    backgroundColor: chartColors.success + '20',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Attack Traffic (Packets/sec)',
                    data: [],
                    borderColor: chartColors.danger,
                    backgroundColor: chartColors.danger + '20',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#e2e8f0' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.1)' }
                    },
                    y: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        min: 0,
                        max: 1000,
                        title: {
                            display: true,
                            text: 'Packets/sec',
                            color: '#94a3b8'
                        }
                    }
                }
            }
        });
        
        // Initialize attack distribution chart (only shows actual attacks)
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        const attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: ['SYN Flood', 'HTTP Flood', 'UDP Flood', 'Slowloris', 'DNS Amplification'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        chartColors.danger,
                        chartColors.danger,
                        chartColors.warning,
                        chartColors.warning,
                        chartColors.danger
                    ],
                    borderWidth: 2,
                    borderColor: 'rgba(15, 23, 42, 0.8)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#e2e8f0' }
                    }
                }
            }
        });
        
        // Initially hide the attack distribution chart container (will show when attacks are detected)
        const attackChartCanvas = document.getElementById('attackChart');
        const chartContainer = attackChartCanvas ? attackChartCanvas.closest('.chart-container') : null;
        if (chartContainer) {
            chartContainer.style.display = 'none';
        }
        
        // Update dashboard data
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    // Update statistics
                    document.getElementById('total-requests').textContent = data.total_requests;
                    document.getElementById('threats-detected').textContent = data.threats_detected;
                    document.getElementById('blocked-ips').textContent = data.blocked_ips;
                    document.getElementById('mitigation-rate').textContent = data.mitigation_rate;
                    document.getElementById('ai-mitigations').textContent = data.ai_mitigations || 0;
                    
                    // Update AI agent status
                    const aiStatusText = document.getElementById('ai-status-text');
                    const aiMitigations = data.ai_mitigations || 0;
                    if (aiMitigations > 0) {
                        aiStatusText.innerHTML = `<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Active</span> - ${aiMitigations} AI-powered decisions made`;
                    } else {
                        aiStatusText.innerHTML = `<span style="color: #f59e0b;"><i class="fas fa-clock"></i> Ready</span> - Waiting for attacks to analyze`;
                    }
                    
                    // Update uptime
                    const uptime = Math.floor(data.uptime || 0);
                    const hours = Math.floor(uptime / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    document.getElementById('uptime-display').textContent = ` | Uptime: ${hours}h ${minutes}m`;
                })
                .catch(error => console.error('Error fetching stats:', error));
            
            // Update AI decisions history
            fetch('/api/mitigation-history')
                .then(response => response.json())
                .then(data => {
                    const decisionsList = document.getElementById('ai-decisions-list');
                    const aiDecisions = data.filter(m => m.ai_powered === true || m.ai_powered === 'true');
                    
                    if (aiDecisions.length === 0) {
                        decisionsList.innerHTML = `
                            <div style="text-align: center; padding: 20px; color: #94a3b8; font-size: 0.9em;">
                                <i class="fas fa-clock"></i> Waiting for AI decisions...
                            </div>
                        `;
                        return;
                    }
                    
                    // Data is already sorted DESC from API, just take latest 5 AI decisions
                    decisionsList.innerHTML = aiDecisions.slice(0, 5).map(decision => {
                        const time = new Date(decision.timestamp * 1000).toLocaleString();
                        const actionColor = decision.action === 'BLOCK' ? '#ef4444' : 
                                          decision.action === 'RATE_LIMIT' ? '#f59e0b' : '#10b981';
                        const statusColor = decision.status === 'MITIGATED' ? '#10b981' : 
                                          decision.status === 'FAILED' ? '#ef4444' : '#f59e0b';
                        const actionIcon = decision.action === 'BLOCK' ? 'fa-ban' : 
                                         decision.action === 'RATE_LIMIT' ? 'fa-tachometer-alt' : 'fa-eye';
                        
                        return `
                            <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; margin-bottom: 10px; border-radius: 8px; border-left: 3px solid ${actionColor};">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <i class="fas ${actionIcon}" style="color: ${actionColor};"></i>
                                        <strong style="color: ${actionColor};">${decision.action}</strong>
                                        <span style="background: ${statusColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold;">
                                            ${decision.status}
                                        </span>
                                    </div>
                                    <span style="color: #94a3b8; font-size: 0.85em;">${time}</span>
                                </div>
                                <div style="color: #cbd5e1; font-size: 0.9em; margin-bottom: 6px;">
                                    <strong>IP:</strong> ${decision.source_ip}
                                </div>
                                <div style="color: #cbd5e1; font-size: 0.85em; margin-bottom: 6px;">
                                    <strong>Command:</strong> <code style="background: rgba(0, 0, 0, 0.3); padding: 2px 6px; border-radius: 4px; color: #fbbf24;">${decision.command || 'N/A'}</code>
                                    ${decision.command && decision.command.includes('Executed via AI tool') ? '<span style="color: #10b981; margin-left: 8px;"><i class="fas fa-check-circle"></i> Executed</span>' : ''}
                                    ${decision.command && !decision.command.includes('Executed via AI tool') && !decision.command.includes('would be') ? '<span style="color: #10b981; margin-left: 8px;"><i class="fas fa-check-circle"></i> Executed</span>' : ''}
                                    ${decision.command && decision.command.includes('would be') ? '<span style="color: #f59e0b; margin-left: 8px;"><i class="fas fa-exclamation-triangle"></i> Simulated</span>' : ''}
                                </div>
                                ${decision.reasoning ? `
                                    <div style="background: rgba(139, 92, 246, 0.1); padding: 8px; border-radius: 6px; margin-top: 6px; border-left: 2px solid rgba(139, 92, 246, 0.5);">
                                        <div style="color: #a78bfa; font-size: 0.85em; font-weight: bold; margin-bottom: 4px;">
                                            <i class="fas fa-brain"></i> AI Reasoning:
                                        </div>
                                        <div style="color: #cbd5e1; font-size: 0.85em; line-height: 1.4;">
                                            ${decision.reasoning}
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    }).join('');
                })
                .catch(error => console.error('Error fetching mitigation history:', error));
            
            // Update traffic chart (real-time: last 20 seconds only)
            fetch('/api/traffic')
                .then(response => response.json())
                .then(data => {
                    if (data.length > 0) {
                        // Data is already sorted by timestamp from API
                        // Create real-time labels (seconds ago, most recent first)
                        const currentTime = Date.now() / 1000;
                        const labels = data.map(d => {
                            const secondsAgo = Math.floor(currentTime - d.timestamp);
                            if (secondsAgo <= 0) return 'now';
                            if (secondsAgo === 1) return '1s ago';
                            return `${secondsAgo}s ago`;
                        });
                        
                        // Extract packet_rate from features array (features[0] is packet_rate)
                        const normalTraffic = data.map(d => {
                            if (d.prediction === 0) {
                                if (d.features && Array.isArray(d.features) && d.features.length > 0) {
                                    return Math.round(d.features[0] || 0); // packet_rate
                                }
                                // Fallback: if no features, return 0
                                return 0;
                            }
                            return null; // null values won't be plotted
                        });
                        const attackTraffic = data.map(d => {
                            if (d.prediction > 0) {
                                if (d.features && Array.isArray(d.features) && d.features.length > 0) {
                                    return Math.round(d.features[0] || 0); // packet_rate
                                }
                                // Fallback: if no features, return 0
                                return 0;
                            }
                            return null; // null values won't be plotted
                        });
                        
                        // Update chart with real-time data
                        trafficChart.data.labels = labels;
                        trafficChart.data.datasets[0].data = normalTraffic;
                        trafficChart.data.datasets[1].data = attackTraffic;
                        // Force update with animation to ensure Y-axis scale is applied
                        trafficChart.update();
                    } else {
                        // No real-time data, clear chart
                        trafficChart.data.labels = [];
                        trafficChart.data.datasets[0].data = [];
                        trafficChart.data.datasets[1].data = [];
                        trafficChart.update('none');
                    }
                })
                .catch(error => console.error('Error fetching traffic:', error));
            
            // Update attack distribution (only show when there are actual attacks)
            fetch('/api/attack-distribution')
                .then(response => response.json())
                .then(data => {
                    // Filter out Normal and check if there are any actual attacks
                    const attackTypes = ['SYN_Flood', 'HTTP_Flood', 'UDP_Flood', 'Slowloris', 'DNS_Amplification'];
                    const attackCounts = attackTypes.map(type => data[type] || 0);
                    const totalAttacks = attackCounts.reduce((sum, count) => sum + count, 0);
                    
                    // Find the attack distribution chart container (parent of attackChart)
                    const attackChartCanvas = document.getElementById('attackChart');
                    const chartContainer = attackChartCanvas ? attackChartCanvas.closest('.chart-container') : null;
                    
                    // Only show chart if there are actual attacks
                    if (totalAttacks > 0) {
                        // Show chart container
                        if (chartContainer) {
                            chartContainer.style.display = 'block';
                        }
                        
                        // Update chart with only attack types (no Normal)
                        attackChart.data.labels = attackTypes;
                        attackChart.data.datasets[0].data = attackCounts;
                        attackChart.update();
                    } else {
                        // Hide chart container when no attacks
                        if (chartContainer) {
                            chartContainer.style.display = 'none';
                        }
                    }
                })
                .catch(error => console.error('Error fetching attack distribution:', error));
            
            // Update alerts
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('alerts-container');
                    
                    if (data.length === 0) {
                        container.innerHTML = `
                            <div style="text-align: center; padding: 40px; color: #94a3b8;">
                                <i class="fas fa-check-circle" style="font-size: 2em; margin-bottom: 10px; color: #10b981;"></i>
                                <p>No threats detected. System secure.</p>
                            </div>
                        `;
                        return;
                    }
                    
                    // Data is already sorted DESC from API, just take latest 5
                    container.innerHTML = data.slice(0, 5).map(alert => {
                        const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
                        const severityClass = `alert-${alert.severity}`;
                        const actionClass = `action-${alert.mitigation_action || 'PENDING'}`;
                        // Get AI info - check multiple possible field names
                        const aiPowered = alert.ai_powered === true || alert.ai_powered === 'true' || false;
                        const aiReasoning = alert.ai_reasoning || alert.reasoning || '';
                        
                        return `
                            <div class="alert-item ${severityClass}">
                                <div class="alert-header">
                                    <span class="alert-type ${alert.attack_type}">
                                        <span class="status-indicator status-${alert.status}"></span>
                                        ${alert.attack_type.replace('_', ' ')}
                                        ${aiPowered ? '<span class="ai-badge"><i class="fas fa-robot"></i> AI Powered</span>' : ''}
                                    </span>
                                    <span class="alert-time">${time}</span>
                                </div>
                                <div class="alert-details">
                                    <div><strong>Source IP:</strong> ${alert.source_ip}</div>
                                    <div><strong>Severity:</strong> ${alert.severity}</div>
                                    <div><strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%</div>
                                    ${alert.mitigation_action ? `<div class="alert-action ${actionClass}"><i class="fas fa-shield-alt"></i> ${alert.mitigation_action}</div>` : ''}
                                    ${aiReasoning ? `<div class="ai-reasoning"><strong>AI Analysis:</strong> ${aiReasoning}</div>` : ''}
                                    ${!aiPowered && alert.mitigation_action ? '<div style="margin-top: 8px; font-size: 0.85em; color: #94a3b8;"><i class="fas fa-cog"></i> Rule-based decision</div>' : ''}
                                </div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(error => console.error('Error fetching alerts:', error));
        }
        
        // Reset stats function
        function resetStats() {
            if (!confirm('Are you sure you want to reset all dashboard stats? This will clear all alerts, mitigation history, and reset counters.')) {
                return;
            }
            
            const statusDiv = document.getElementById('attack-status');
            statusDiv.className = 'attack-status';
            statusDiv.textContent = 'Resetting dashboard stats...';
            statusDiv.classList.add('success');
            
            fetch('/api/reset-stats', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusDiv.textContent = 'Dashboard stats reset successfully!';
                    statusDiv.classList.remove('success');
                    statusDiv.classList.add('success');
                    // Refresh dashboard immediately
                    setTimeout(updateDashboard, 300);
                } else {
                    statusDiv.textContent = `Error: ${data.message || 'Failed to reset stats'}`;
                    statusDiv.classList.remove('success');
                    statusDiv.classList.add('error');
                }
                // Hide status after 3 seconds
                setTimeout(() => {
                    statusDiv.className = 'attack-status';
                }, 3000);
            })
            .catch(error => {
                statusDiv.textContent = `Error: ${error.message}`;
                statusDiv.classList.remove('success');
                statusDiv.classList.add('error');
                setTimeout(() => {
                    statusDiv.className = 'attack-status';
                }, 3000);
            });
        }
        
        // Attack generator function
        function triggerAttack(attackType) {
            const statusDiv = document.getElementById('attack-status');
            statusDiv.className = 'attack-status';
            statusDiv.textContent = `Generating ${attackType} attack...`;
            statusDiv.classList.add('success');
            
            fetch('/api/trigger-attack', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ attack_type: attackType })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusDiv.textContent = `${attackType} attack generated successfully! Check alerts below.`;
                    statusDiv.classList.remove('success');
                    statusDiv.classList.add('success');
                    // Refresh dashboard after a short delay
                    setTimeout(updateDashboard, 500);
                } else {
                    statusDiv.textContent = `Error: ${data.message || 'Failed to generate attack'}`;
                    statusDiv.classList.remove('success');
                    statusDiv.classList.add('error');
                }
                // Hide status after 3 seconds
                setTimeout(() => {
                    statusDiv.className = 'attack-status';
                }, 3000);
            })
            .catch(error => {
                statusDiv.textContent = `Error: ${error.message}`;
                statusDiv.classList.remove('success');
                statusDiv.classList.add('error');
                setTimeout(() => {
                    statusDiv.className = 'attack-status';
                }, 3000);
            });
        }
        
        // Initial load and periodic updates
        updateDashboard();
        setInterval(updateDashboard, 3000);
    </script>
</body>
</html>
'''

# Global start time
start_time = time.time()

# API endpoints
@app.route('/')
def index():
    return render_template_string(dashboard_template)

@app.route('/api/stats')
def get_stats():
    return jsonify(calculate_statistics())

@app.route('/api/traffic')
def get_traffic():
    """Get real-time traffic data from the last 20 seconds only.
    Only shows attack traffic if it appears in Recent Alerts (has corresponding alert in database)."""
    current_time = time.time()
    twenty_seconds_ago = current_time - 20  # Last 20 seconds for real-time view
    
    # Get all alerts from database to cross-reference
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, attack_type FROM alerts 
        WHERE timestamp >= ?
    ''', (twenty_seconds_ago,))
    alerts_data = cursor.fetchall()
    conn.close()
    
    # Create a set of alert timestamps with ±2 second window for matching
    # This allows matching traffic that was created slightly before/after the alert
    alert_timestamps = set()
    for alert_ts, attack_type in alerts_data:
        # Allow ±2 second window for matching (traffic might be logged slightly before alert)
        for offset in range(-2, 3):
            alert_timestamps.add((int(alert_ts) + offset, attack_type))
    
    # Filter traffic buffer to only include data from last 20 seconds
    recent_traffic = []
    for traffic in traffic_buffer:
        traffic_ts = traffic.get('timestamp', 0)
        if traffic_ts >= twenty_seconds_ago:
            prediction = traffic.get('prediction', 0)
            attack_type = traffic.get('attack_type', 'Normal')
            
            # Always include normal traffic (prediction == 0)
            if prediction == 0:
                recent_traffic.append(traffic)
            # Only include attack traffic if there's a corresponding alert
            elif (int(traffic_ts), attack_type) in alert_timestamps:
                recent_traffic.append(traffic)
    
    # Sort by timestamp (oldest first) and limit to latest 20 data points max
    recent_traffic.sort(key=lambda x: x.get('timestamp', 0))
    recent_traffic = recent_traffic[-20:]  # Keep only last 20 data points
    
    return jsonify(recent_traffic)

@app.route('/api/alerts')
def get_alerts():
    """Fetch alerts from database with AI information"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get latest 5 alerts ordered by timestamp (most recent first)
    cursor.execute('''
        SELECT * FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 5
    ''')
    
    alerts_list = []
    for row in cursor.fetchall():
        alert_dict = dict(row)
        # Convert features to dict format for compatibility
        alert_dict['features'] = {
            'packet_rate': alert_dict.get('packet_rate'),
            'byte_rate': alert_dict.get('byte_rate'),
            'connection_rate': alert_dict.get('connection_rate')
        }
        # Convert ai_powered from integer to boolean
        alert_dict['ai_powered'] = bool(alert_dict.get('ai_powered', 0))
        # Remove None values for cleaner JSON
        if alert_dict.get('ai_reasoning') is None:
            alert_dict['ai_reasoning'] = ''
        alerts_list.append(alert_dict)
    
    conn.close()
    return jsonify(alerts_list)

@app.route('/api/attack-distribution')
def get_attack_distribution():
    stats = calculate_statistics()
    return jsonify(stats['attack_distribution'])

@app.route('/api/mitigation-history')
def get_mitigation_history():
    """Fetch mitigation history from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get latest 5 mitigation records ordered by timestamp (most recent first)
    cursor.execute('''
        SELECT * FROM mitigation_history 
        ORDER BY timestamp DESC 
        LIMIT 5
    ''')
    
    mitigation_list = []
    for row in cursor.fetchall():
        mitigation_dict = dict(row)
        # Convert ai_powered from integer to boolean
        mitigation_dict['ai_powered'] = bool(mitigation_dict.get('ai_powered', 0))
        mitigation_list.append(mitigation_dict)
    
    conn.close()
    return jsonify(mitigation_list)

@app.route('/api/trigger-attack', methods=['POST'])
def trigger_attack():
    """API endpoint to manually trigger an attack for testing"""
    try:
        data = request.get_json()
        attack_type = data.get('attack_type')
        
        if not attack_type:
            return jsonify({'success': False, 'message': 'Attack type not specified'}), 400
        
        valid_attack_types = ['SYN_Flood', 'HTTP_Flood', 'UDP_Flood', 'Slowloris', 'DNS_Amplification']
        if attack_type not in valid_attack_types:
            return jsonify({'success': False, 'message': f'Invalid attack type. Valid types: {", ".join(valid_attack_types)}'}), 400
        
        logger.info(f"Manually triggering {attack_type} attack")
        traffic_data = generate_attack_traffic(attack_type)
        
        return jsonify({
            'success': True,
            'message': f'{attack_type} attack generated successfully',
            'traffic_data': {
                'attack_type': traffic_data['attack_type'],
                'confidence': traffic_data['confidence'],
                'attack_probability': traffic_data['attack_probability']
            }
        })
    except Exception as e:
        logger.error(f"Error triggering attack: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/reset-stats', methods=['POST'])
def reset_stats():
    """API endpoint to reset all dashboard stats by clearing the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Clear all alerts
        cursor.execute('DELETE FROM alerts')
        
        # Clear all mitigation history
        cursor.execute('DELETE FROM mitigation_history')
        
        # Reset stats table (set total_requests to 0, ensure it exists)
        cursor.execute('''
            INSERT OR REPLACE INTO stats (key, value, updated_at) 
            VALUES ('total_requests', 0, CURRENT_TIMESTAMP)
        ''')
        
        # Clear any other stats if they exist
        cursor.execute('DELETE FROM stats WHERE key != ?', ('total_requests',))
        
        conn.commit()
        conn.close()
        
        logger.info("Dashboard stats reset: All alerts, mitigation history, and stats cleared")
        
        return jsonify({
            'success': True,
            'message': 'All dashboard stats have been reset successfully'
        })
    except Exception as e:
        logger.error(f"Error resetting stats: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    # Initialize ML log file with header
    initialize_ml_log_file()
    logger.info("ML model output logging initialized to ml_model_output.log")
    
    # Start the traffic monitoring thread
    traffic_thread = threading.Thread(target=simulate_network_traffic, daemon=True)
    traffic_thread.start()
    
    logger.info("Starting DDOS Shield server...")
    logger.info("Dashboard available at: http://localhost:8888")
    
    app.run(debug=True, host='0.0.0.0', port=8888)