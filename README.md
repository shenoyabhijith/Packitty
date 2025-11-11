# DDOS Shield - Real-time Detection & Mitigation System

A comprehensive ML-powered DDOS detection and automated mitigation system with real-time monitoring dashboard.

## Features

- **Real-time Detection**: Identifies 5 types of DDOS attacks using machine learning
- **Automated Mitigation**: LLM-powered agent executes firewall commands
- **Live Dashboard**: Real-time visualization of network traffic and threats
- **Attack Types Detected**:
  - SYN Flood
  - HTTP Flood  
  - UDP Flood
  - Slowloris
  - DNS Amplification

## Architecture

```
Traffic Monitor → ML Classifier → Alert System → LLM Agent → UFW Execution
                                      ↓
                               Frontend Dashboard
```

## Quick Start

### 1. Environment Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Train the ML Model

```bash
python train_model.py
```

This will:
- Generate synthetic training data
- Train a Random Forest classifier
- Save the model as `ddos_model.pkl`

### 3. Run the Application

```bash
python app.py
```

The dashboard will be available at: `http://localhost:8888`

## System Components

### Backend (app.py)
- **Flask Server**: Web interface and API endpoints
- **ML Classifier**: Real-time traffic analysis using scikit-learn
- **Traffic Simulator**: Generates realistic network traffic patterns
- **Alert System**: Creates alerts for detected threats
- **Mitigation Engine**: Simulates firewall rule execution

### ML Model (train_model.py)
- **Features**: 8 network traffic characteristics
- **Algorithm**: Random Forest Classifier
- **Classes**: Normal + 5 attack types
- **Accuracy**: ~95% on synthetic data

### Dashboard Features
- **Real-time Statistics**: Request counts, threat detection, blocked IPs
- **Traffic Visualization**: Live charts showing normal vs attack traffic
- **Attack Distribution**: Pie chart of detected attack types
- **Alert History**: Recent threats with mitigation actions
- **System Status**: Uptime and health monitoring

## Configuration

### Environment Variables
```bash
# For LLM integration (optional)
export GEMINI_API_KEY="your-api-key"

# For production deployment
export FLASK_ENV=production
```

### Customization
- Modify `simulate_network_traffic()` in `app.py` to use real network data
- Update firewall commands in `execute_mitigation()` for production use
- Adjust ML model parameters in `train_model.py`

## Production Deployment

### Security Considerations
1. **Authentication**: Add user authentication for dashboard access
2. **HTTPS**: Use SSL certificates for secure communication
3. **Firewall**: Configure UFW with proper rules
4. **Monitoring**: Set up logging and alerting
5. **Updates**: Regular security updates for dependencies

### Real Traffic Integration
Replace the traffic simulator with real network monitoring:

```python
# Using scapy for packet capture
from scapy.all import sniff

def capture_real_traffic():
    def process_packet(packet):
        # Extract features from packet
        features = extract_packet_features(packet)
        prediction = model.predict([features])[0]
        # Process detection...
    
    sniff(prn=process_packet, filter="ip")
```

### Firewall Integration
Uncomment and configure UFW commands in `execute_mitigation()`:

```python
# Real UFW execution
result = subprocess.run(['sudo', 'ufw', 'deny', 'from', source_ip], 
                       capture_output=True, text=True)
```

## API Endpoints

- `GET /` - Dashboard interface
- `GET /api/stats` - System statistics
- `GET /api/traffic` - Recent traffic data
- `GET /api/alerts` - Alert history
- `GET /api/attack-distribution` - Attack type distribution
- `GET /api/mitigation-history` - Mitigation actions log

## Monitoring & Maintenance

### Health Checks
- Monitor system resources (CPU, memory, network)
- Check model prediction accuracy
- Verify firewall rule effectiveness
- Review alert frequency and false positives

### Model Updates
- Retrain model with new attack patterns
- Update feature extraction methods
- Validate against latest threat intelligence

## Troubleshooting

### Common Issues
1. **Model not found**: Run `train_model.py` first
2. **Port already in use**: Change port in `app.py`
3. **Permission errors**: Run with appropriate privileges for firewall access

### Performance Optimization
- Adjust traffic buffer size for memory constraints
- Enable model caching for faster predictions
- Use connection pooling for database operations

## License

This project is for educational and research purposes. Use responsibly in authorized environments only.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Disclaimer

This system is designed for educational purposes and network security research. Ensure you have proper authorization before deploying in any network environment.