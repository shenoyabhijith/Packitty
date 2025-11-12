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
            attack_type TEXT,
            reasoning TEXT,
            ai_powered INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # Add attack_type column if it doesn't exist (migration for existing databases)
    try:
        cursor.execute('ALTER TABLE mitigation_history ADD COLUMN attack_type TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
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
TEST_MODE_NORMAL_ONLY = True  # Only generate normal traffic; attacks via manual trigger only

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
            # Reduced attack probability: 95% normal, 1% per attack type (5% total attacks)
            traffic_type = np.random.choice([0, 1, 2, 3, 4, 5], p=[0.95, 0.01, 0.01, 0.01, 0.01, 0.01])
        
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
        (timestamp, alert_id, action, command, status, source_ip, attack_type, reasoning, ai_powered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        time.time(),
        alert['id'],
        action,
        ufw_command,
        status,
        source_ip,
        attack_type,
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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-weight: 200;
            background: radial-gradient(ellipse at bottom, #5091DD 0%, #030617 100%);
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
            height: 100%;
            position: relative;
            overflow-x: hidden;
        }
        
        /* Grid pattern overlay */
        #grid {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 1px;
            pointer-events: none;
            z-index: 0;
        }
        
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 20px;
            position: relative;
            z-index: 1;
        }
        
        .header {
            text-align: center;
            padding: 30px 0 40px;
            background: rgba(30, 41, 59, 0.5);
            border-radius: 16px;
            margin-bottom: 40px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        }
        
        .header h1 {
            font-size: 40px;
            font-weight: 700;
            margin-bottom: 15px;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: 2px;
        }
        
        .header p {
            font-size: 1.05em;
            color: #94a3b8;
            margin: 0;
            padding: 20px 0 0 0;
        }
        
        .section-divider {
            height: 1px;
            background: rgba(255, 255, 255, 0.1);
            margin: 40px 0;
            border: none;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%);
            padding: 30px 25px;
            border-radius: 16px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 12px;
            text-shadow: 0 0 20px currentColor;
        }
        
        .stat-value.high { 
            color: #ff6b6b;
            text-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
        }
        .stat-value.medium { 
            color: #ffd93d;
            text-shadow: 0 0 20px rgba(245, 158, 11, 0.6);
        }
        .stat-value.low { 
            color: #6bcf7f;
            text-shadow: 0 0 20px rgba(16, 185, 129, 0.6);
        }
        .stat-value.info { 
            color: #6b9fff;
            text-shadow: 0 0 20px rgba(59, 130, 246, 0.6);
        }
        
        .stat-label {
            color: #cbd5e1;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .chart-container {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%);
            padding: 30px;
            border-radius: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        .chart-container h3 {
            margin-bottom: 25px;
            color: #e2e8f0;
            font-size: 1.3em;
            font-weight: 600;
        }
        
        .alerts-section {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%);
            padding: 30px;
            border-radius: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
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
            animation: pulseGlow 2s ease-in-out infinite;
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.5);
        }
        
        @keyframes pulseGlow {
            0%, 100% { 
                box-shadow: 0 0 15px rgba(139, 92, 246, 0.5);
                transform: scale(1);
            }
            50% { 
                box-shadow: 0 0 25px rgba(139, 92, 246, 0.8);
                transform: scale(1.05);
            }
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
            box-shadow: 0 0 8px currentColor;
        }
        
        .status-MITIGATED { 
            background: #10b981;
            box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
        }
        .status-DETECTED { 
            background: #f59e0b;
            animation: pulse 2s infinite;
            box-shadow: 0 0 8px rgba(245, 158, 11, 0.6);
        }
        .status-FAILED { 
            background: #ef4444;
            box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
        }
        
        @keyframes pulse {
            0%, 100% { 
                opacity: 1;
                transform: scale(1);
            }
            50% { 
                opacity: 0.7;
                transform: scale(1.2);
            }
        }
        
        .system-status {
            text-align: center;
            padding: 18px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 12px;
            margin-top: 30px;
            position: relative;
        }
        
        .system-status.active {
            background: rgba(16, 185, 129, 0.1);
            border-color: rgba(16, 185, 129, 0.3);
            color: #10b981;
        }
        
        .system-status.active::before {
            content: '';
            position: absolute;
            left: 20px;
            top: 50%;
            transform: translateY(-50%);
            width: 10px;
            height: 10px;
            background: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.8);
            animation: pulse 2s infinite;
        }
        
        .attack-generator {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%);
            padding: 30px;
            border-radius: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
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
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 25px;
        }
        
        .attack-btn {
            padding: 16px 24px;
            border: none;
            border-radius: 12px;
            font-size: 0.95em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            min-height: 50px;
        }
        
        .attack-btn i {
            font-size: 1.1em;
        }
        
        .attack-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
            filter: brightness(1.1);
        }
        
        .attack-btn:active {
            transform: translateY(0);
        }
        
        .attack-btn.syn-flood {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        
        .attack-btn.http-flood {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            color: white;
        }
        
        .attack-btn.udp-flood {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
        }
        
        .attack-btn.slowloris {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            color: white;
        }
        
        .attack-btn.dns-amplification {
            background: linear-gradient(135deg, #ec4899 0%, #db2777 100%);
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
                font-size: 32px;
            }
            
            .container {
                padding: 10px;
            }
        }
        
        /* Cat Logo Styles */
        .cat.container {
            position: relative;
            background-color: transparent;
            height: 120px;
            width: 150px;
            z-index: 1;
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        .cat.head {
            position: absolute;
            background-color: #f3f3f3;
            top: 50%;
            left: 50%;
            border: 2px solid black;
            height: 108px;
            width: 126px;
            border-radius: 60% 60% 50% 50%;
            transform: translate(-50%, -50%);
        }
        
        .cat.ears {
            position: absolute;
            background-color: pink;
            top: 50%;
            left: 50%;
        }
        
        .cat.ears::before {
            content: "";
            position: absolute;
            background-color: pink;
            margin-left: -21px;
            border: 2px solid black;
            height: 90px;
            width: 90px;
            background-clip: content-box;
            box-shadow: inset 0 0 0 9px #f3f3f3;
            border-radius: 5px 90% 0 90%;
            transform: skewX(10deg);
            transform: skewY(10deg);
            transform: translate(-50%, -65%);
        }
        
        .cat.ears::after {
            content: "";
            position: absolute;
            background-color: pink;
            margin-left: 21px;
            border: 2px solid black;
            height: 90px;
            width: 90px;
            background-clip: content-box;
            box-shadow: inset 0 0 0 9px #f3f3f3;
            border-radius: 90% 5px 90% 0;
            transform: skewX(-10deg);
            transform: skewY(-10deg);
            transform: translate(-50%, -65%);
        }
        
        .cat.face {
            position: absolute;
            background-color: #fff;
            top: 60%;
            left: 50%;
            transform: translate(-50%, -50%);
            height: 54px;
            width: 60px;
            border-radius: 50%;
        }
        
        .cat.eyes {
            position: relative;
            background-color: transparent;
            top: 20%;
            left: 50%;
            transform: translate(-50%, -50%);
            height: 18px;
            width: 18px;
            border-radius: 50%;
            box-shadow: -30px 6px 0 #000, 30px 6px 0 #000;
        }
        
        .cat.nose {
            position: relative;
            background-color: pink;
            top: 20%;
            left: 50%;
            transform: translate(-50%, -50%);
            height: 6px;
            width: 9px;
            border-radius: 50%;
        }
        
        .cat.mouth {
            position: relative;
            top: 30%;
            left: 50%;
            transform: translate(-50%, -50%);
            height: 4px;
            width: 8px;
        }
        
        .cat.mouth::before {
            content: "";
            position: absolute;
            left: 0px;
            transform: translate(-50%, -50%);
            border: 2px solid black;
            height: 4px;
            width: 8px;
            border-radius: 0 0 125px 125px;
            border-top: none;
        }
        
        .cat.mouth::after {
            content: "";
            position: absolute;
            left: 9px;
            transform: translate(-50%, -50%);
            border: 2px solid black;
            height: 4px;
            width: 8px;
            border-radius: 0 0 125px 125px;
            border-top: none;
        }
        
        .cat.body {
            position: absolute;
            background-color: #f3f3f3;
            top: 50%;
            left: 50%;
            transform: translate(-50%, 70%);
            border: 2px solid black;
            height: 54px;
            width: 54px;
            border-radius: 50% 50% 25px 25px;
            z-index: -1;
        }
        
        .cat.body::before {
            content: "";
            position: absolute;
            background-color: #fff;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -80%);
            height: 36px;
            width: 36px;
            z-index: 3;
            border-radius: 50%;
            border-top: none;
        }
        
        .cat.frontleg {
            position: absolute;
            top: 50%;
            left: 50%;
            margin: 81px 0 0 0;
            transform: translate(-50%, -50%);
            width: 12px;
        }
        
        .cat.frontleg::before {
            content: "";
            position: absolute;
            background-color: #f3f3f3;
            left: -90%;
            height: 18px;
            width: 12px;
            border: 2px solid black;
            border-radius: 0 0 50% 50%;
            border-top: none;
        }
        
        .cat.frontleg::after {
            content: "";
            position: absolute;
            background-color: #f3f3f3;
            left: 90%;
            height: 18px;
            width: 12px;
            border: 2px solid black;
            border-radius: 0 0 50% 50%;
            border-top: none;
        }
        
        .cat.backleg {
            position: absolute;
            background-color: #f3f3f3;
            top: 50%;
            left: 50%;
            margin: 92px 0 0 0;
            z-index: -2;
        }
        
        .cat.backleg::before {
            content: "";
            position: absolute;
            background-color: #f3f3f3;
            top: -6px;
            left: -36px;
            width: 7px;
            height: 7px;
            border: 2px solid black;
            border-radius: 50% 0 0 50%;
            transform: skewX(-10deg);
            transform: skewY(-10deg);
        }
        
        .cat.backleg::after {
            content: "";
            position: absolute;
            background-color: #f3f3f3;
            top: -6px;
            left: 24px;
            width: 7px;
            height: 7px;
            border: 2px solid black;
            border-radius: 0 50% 50% 0;
            transform: skewX(10deg);
            transform: skewY(10deg);
        }
        
        .cat.tail {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            margin: 78px 0 0 -54px;
            z-index: -2;
        }
        
        .cat.tail::before {
            content: "";
            position: absolute;
            background-color: #f3f3f3;
            width: 25px;
            height: 7px;
            border: 2px solid black;
            border-radius: 30px 0 0 50px;
            transform: rotate(50deg);
            transform-origin: right center;
        }
        
        .cat.tail::after {
            content: "";
            position: absolute;
            background-color: #fff;
            margin: -12px 0 0 11px;
            width: 7px;
            height: 7px;
            border-radius: 30px 0 0 50px;
            transform: rotate(50deg);
            transform-origin: right center;
        }
    </style>
</head>
<body>
    <div id="grid"></div>
    <div class="container">
        <div class="header">
            <div class="cat container">
                <div class="cat ears"></div>
                <div class="cat head">
                    <div class="cat face">
                        <div class="cat eyes"></div>
                        <div class="cat nose"></div>
                        <div class="cat mouth"></div>
                    </div>
                </div>
                <div class="cat body"></div>
                <div class="cat frontleg"></div>
                <div class="cat backleg"></div>
                <div class="cat tail"></div>
            </div>
            <p>Packitty a Real-time ML-Powered Threat Detection & Automated Mitigation</p>
        </div>
        
        <hr class="section-divider">
        
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
            <div class="stat-card" style="position: relative;">
                <div class="stat-value" id="ai-mitigations" style="color: #8b5cf6; text-shadow: 0 0 20px rgba(139, 92, 246, 0.6);">0</div>
                <div class="stat-label"><i class="fas fa-robot"></i> AI-Powered</div>
            </div>
        </div>
        
        <hr class="section-divider">
        
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
        
        <hr class="section-divider">
        
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
        
        <hr class="section-divider">
        
        <div class="alerts-section">
            <h3><i class="fas fa-exclamation-triangle"></i> Recent Alerts</h3>
            <div id="alerts-container">
                <div style="text-align: center; padding: 40px; color: #94a3b8;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 2em; margin-bottom: 10px;"></i>
                    <p>Monitoring for threats...</p>
                </div>
            </div>
        </div>
        
        <hr class="section-divider">
        
        <div class="ai-agent-status" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 16px; padding: 25px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);">
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
                        <i class="fas fa-spinner fa-spin" style="margin-right: 8px;"></i> Waiting for AI decisions...
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
        // Generate grid pattern dynamically
        function generateGridPattern() {
            const grid = document.getElementById('grid');
            if (!grid) return;
            
            const lineColor = '#030617';
            const step = 3;
            const viewportHeight = Math.max(document.documentElement.clientHeight, window.innerHeight || 0);
            const viewportWidth = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
            const numHorizontalLines = Math.ceil(viewportHeight / step);
            const numVerticalLines = Math.ceil(viewportWidth / step);
            
            // Generate horizontal lines (vertical box-shadow)
            let horizontalShadows = '0px 0px ' + lineColor;
            for (let i = 1; i <= numHorizontalLines; i++) {
                horizontalShadows += ', 0px ' + (step * i) + 'px ' + lineColor;
            }
            grid.style.boxShadow = horizontalShadows;
            
            // Generate vertical lines (horizontal box-shadow)
            let verticalShadows = '0px 0px ' + lineColor;
            for (let i = 1; i <= numVerticalLines; i++) {
                verticalShadows += ', ' + (step * i) + 'px 0px ' + lineColor;
            }
            
            // Create pseudo-element for vertical lines
            const style = document.createElement('style');
            style.textContent = `
                #grid::after {
                    content: "";
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 1px;
                    height: 100%;
                    box-shadow: ${verticalShadows};
                }
            `;
            document.head.appendChild(style);
        }
        
        // Generate grid on load and resize
        window.addEventListener('load', generateGridPattern);
        window.addEventListener('resize', generateGridPattern);
        
        // Chart configurations
        const chartColors = {
            primary: '#3b82f6',
            secondary: '#8b5cf6',
            success: '#10b981',
            warning: '#f59e0b',
            danger: '#ef4444',
            info: '#06b6d4'
        };
        
        // Attack type colors - matching button colors
        const attackColors = {
            'SYN_Flood': '#ef4444',        // Red - matches syn-flood button
            'HTTP_Flood': '#8b5cf6',       // Purple - matches http-flood button
            'UDP_Flood': '#f59e0b',        // Orange/Amber - matches udp-flood button
            'Slowloris': '#06b6d4',        // Cyan - matches slowloris button
            'DNS_Amplification': '#ec4899' // Pink - matches dns-amplification button
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
                    fill: true,
                    borderWidth: 3
                }, {
                    label: 'Attack Traffic (Packets/sec)',
                    data: [],
                    borderColor: chartColors.danger,
                    backgroundColor: chartColors.danger + '20',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        labels: { 
                            color: '#e2e8f0',
                            font: { size: 12, weight: '500' }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#e2e8f0',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true,
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y + ' packets/sec';
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { 
                            color: '#94a3b8',
                            font: { size: 11 }
                        },
                        grid: { 
                            color: 'rgba(148, 163, 184, 0.15)',
                            lineWidth: 1
                        },
                        title: {
                            display: true,
                            text: 'Time',
                            color: '#94a3b8',
                            font: { size: 12, weight: '500' }
                        }
                    },
                    y: {
                        ticks: { 
                            color: '#94a3b8',
                            font: { size: 11 }
                        },
                        grid: { 
                            color: 'rgba(148, 163, 184, 0.15)',
                            lineWidth: 1
                        },
                        min: 0,
                        max: 1000,
                        title: {
                            display: true,
                            text: 'Packets/sec',
                            color: '#94a3b8',
                            font: { size: 12, weight: '500' }
                        }
                    }
                },
                elements: {
                    line: {
                        borderWidth: 3,
                        tension: 0.4
                    },
                    point: {
                        radius: 3,
                        hoverRadius: 6
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
                        attackColors['SYN_Flood'],        // Red
                        attackColors['HTTP_Flood'],        // Purple
                        attackColors['UDP_Flood'],         // Orange/Amber
                        attackColors['Slowloris'],         // Cyan
                        attackColors['DNS_Amplification']  // Pink
                    ],
                    borderWidth: 2,
                    borderColor: 'rgba(15, 23, 42, 0.8)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false
                },
                plugins: {
                    legend: {
                        labels: { 
                            color: '#e2e8f0',
                            font: { size: 12, weight: '500' }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#e2e8f0',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                return label + ': ' + value;
                            }
                        }
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
                        
                        const attackType = decision.attack_type || 'Unknown';
                        const attackTypeColor = '#f59e0b';
                        
                        return `
                            <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; margin-bottom: 10px; border-radius: 8px; border-left: 3px solid ${actionColor};">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <i class="fas ${actionIcon}" style="color: ${actionColor};"></i>
                                        <strong style="color: ${actionColor};">${decision.action} MITIGATED</strong>
                                        <span style="background: ${statusColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold;">
                                            ${decision.status}
                                        </span>
                                    </div>
                                    <span style="color: #94a3b8; font-size: 0.85em;">${time}</span>
                                </div>
                                <div style="color: #cbd5e1; font-size: 0.9em; margin-bottom: 6px;">
                                    <strong>Attack Type:</strong> <span style="color: ${attackTypeColor}; font-weight: bold;">${attackType}</span>
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
                        // Clamp values to max 1000 to prevent chart breaking
                        // Use 0 instead of null to maintain continuous lines
                        const normalTraffic = data.map(d => {
                            if (d.prediction === 0) {
                                // Normal traffic - show actual packet rate
                                if (d.features && Array.isArray(d.features) && d.features.length > 0) {
                                    const packetRate = Math.round(d.features[0] || 0);
                                    return Math.min(packetRate, 1000); // Clamp to max 1000
                                }
                                return 0;
                            }
                            // During attacks, show 0 for normal traffic to maintain line continuity
                            return 0;
                        });
                        const attackTraffic = data.map(d => {
                            if (d.prediction > 0) {
                                // Attack traffic - show actual packet rate
                                if (d.features && Array.isArray(d.features) && d.features.length > 0) {
                                    const packetRate = Math.round(d.features[0] || 0);
                                    return Math.min(packetRate, 1000); // Clamp to max 1000
                                }
                                return 0;
                            }
                            // During normal traffic, show 0 for attack traffic to maintain line continuity
                            return 0;
                        });
                        
                        // Ensure labels and data arrays have same length
                        if (labels.length !== normalTraffic.length || labels.length !== attackTraffic.length) {
                            console.error('Chart data length mismatch:', {
                                labels: labels.length,
                                normal: normalTraffic.length,
                                attack: attackTraffic.length
                            });
                            // Truncate to shortest length
                            const minLength = Math.min(labels.length, normalTraffic.length, attackTraffic.length);
                            labels.splice(minLength);
                            normalTraffic.splice(minLength);
                            attackTraffic.splice(minLength);
                        }
                        
                        // Update chart with real-time data
                        try {
                            trafficChart.data.labels = labels;
                            trafficChart.data.datasets[0].data = normalTraffic;
                            trafficChart.data.datasets[1].data = attackTraffic;
                            // Use 'none' mode for smoother updates during attacks
                            trafficChart.update('none');
                        } catch (error) {
                            console.error('Error updating traffic chart:', error);
                        }
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
                        // Map attack types to display labels
                        const displayLabels = attackTypes.map(type => type.replace('_', ' '));
                        attackChart.data.labels = displayLabels;
                        attackChart.data.datasets[0].data = attackCounts;
                        // Ensure colors are maintained in correct order
                        attackChart.data.datasets[0].backgroundColor = [
                            attackColors['SYN_Flood'],
                            attackColors['HTTP_Flood'],
                            attackColors['UDP_Flood'],
                            attackColors['Slowloris'],
                            attackColors['DNS_Amplification']
                        ];
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