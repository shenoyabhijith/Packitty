import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import pandas as pd

def generate_synthetic_ddos_data(n_samples=10000):
    """
    Generate synthetic network traffic data for DDOS detection training
    Features simulate realistic network patterns for different attack types
    """
    np.random.seed(42)
    
    # Initialize arrays
    X = np.zeros((n_samples, 8))
    y = np.zeros(n_samples, dtype=int)
    
    # Normal traffic (class 0) - 60% of data
    normal_samples = int(n_samples * 0.6)
    X[:normal_samples] = np.random.normal(
        loc=[100, 50000, 0.1, 0.2, 10, 5, 500, 1000],  # normal traffic patterns
        scale=[20, 10000, 0.05, 0.1, 5, 2, 200, 500],
        size=(normal_samples, 8)
    )
    y[:normal_samples] = 0
    
    # SYN Flood (class 1) - 8% of data
    syn_samples = int(n_samples * 0.08)
    X[normal_samples:normal_samples+syn_samples] = np.random.normal(
        loc=[1000, 80000, 0.9, 0.1, 5, 50, 100, 100],  # high SYN ratio, many connections
        scale=[200, 15000, 0.05, 0.05, 2, 10, 50, 50],
        size=(syn_samples, 8)
    )
    y[normal_samples:normal_samples+syn_samples] = 1
    
    # HTTP Flood (class 2) - 8% of data
    http_samples = int(n_samples * 0.08)
    X[normal_samples+syn_samples:normal_samples+syn_samples+http_samples] = np.random.normal(
        loc=[800, 120000, 0.2, 0.1, 15, 20, 400, 200],  # high packet rate, large payload
        scale=[150, 20000, 0.1, 0.05, 5, 5, 100, 100],
        size=(http_samples, 8)
    )
    y[normal_samples+syn_samples:normal_samples+syn_samples+http_samples] = 2
    
    # UDP Flood (class 3) - 8% of data
    udp_samples = int(n_samples * 0.08)
    X[normal_samples+syn_samples+http_samples:normal_samples+syn_samples+http_samples+udp_samples] = np.random.normal(
        loc=[1200, 100000, 0.1, 0.8, 8, 30, 300, 150],  # high UDP ratio
        scale=[250, 18000, 0.05, 0.1, 3, 8, 80, 80],
        size=(udp_samples, 8)
    )
    y[normal_samples+syn_samples+http_samples:normal_samples+syn_samples+http_samples+udp_samples] = 3
    
    # Slowloris (class 4) - 8% of data
    slow_samples = int(n_samples * 0.08)
    X[normal_samples+syn_samples+http_samples+udp_samples:normal_samples+syn_samples+http_samples+udp_samples+slow_samples] = np.random.normal(
        loc=[200, 30000, 0.3, 0.2, 12, 100, 50, 5000],  # long intervals, many connections
        scale=[50, 8000, 0.1, 0.1, 4, 20, 20, 1000],
        size=(slow_samples, 8)
    )
    y[normal_samples+syn_samples+http_samples+udp_samples:normal_samples+syn_samples+http_samples+udp_samples+slow_samples] = 4
    
    # DNS Amplification (class 5) - 8% of data
    dns_samples = int(n_samples * 0.08)
    X[-dns_samples:] = np.random.normal(
        loc=[600, 150000, 0.1, 0.6, 50, 15, 800, 300],  # high DNS queries, large responses
        scale=[120, 25000, 0.05, 0.1, 10, 5, 200, 150],
        size=(dns_samples, 8)
    )
    y[-dns_samples:] = 5
    
    # Ensure all values are positive
    X = np.abs(X)
    
    return X, y

def train_ddos_model():
    """Train and save the DDOS detection model"""
    print("Generating synthetic training data...")
    X, y = generate_synthetic_ddos_data(10000)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest classifier...")
    # Train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Model accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                              target_names=['Normal', 'SYN_Flood', 'HTTP_Flood', 
                                          'UDP_Flood', 'Slowloris', 'DNS_Amplification']))
    
    # Save the model
    joblib.dump(model, 'ddos_model.pkl')
    print("\nModel saved as 'ddos_model.pkl'")
    
    # Save feature names for reference
    feature_names = [
        'packet_rate',
        'byte_rate', 
        'syn_ratio',
        'udp_ratio',
        'dns_queries',
        'connection_rate',
        'payload_size',
        'request_interval'
    ]
    
    joblib.dump(feature_names, 'feature_names.pkl')
    print("Feature names saved as 'feature_names.pkl'")
    
    return model

if __name__ == "__main__":
    train_ddos_model()