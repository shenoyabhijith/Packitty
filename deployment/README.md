# Deployment Guide

This folder contains deployment procedures for both projects in the Packitty repository.

## Projects

### 1. Packitty DDoS Detection System
Advanced DDoS attack detection using Scapy packet capture.

See: `deployment/packitty/`

**Deployment Options:**
- **Ubuntu Server**: `packitty/ubuntu/` - Single server deployment with systemd
- **AWS Infrastructure**: `packitty/aws/` - Terraform-based AWS EC2 deployment
- **Scripts**: `packitty/scripts/` - Attack simulation and utility scripts

### 2. k3s Flask App
Flask application deployed on k3s Kubernetes with Envoy proxy sidecar.

See: `deployment/k3s-flask-app/`

**Features:**
- Flask web application
- Envoy proxy sidecar (port forwarding)
- Complete Kubernetes manifests
- Docker containerization
- NodePort service for external access

---

## Directory Structure

```
deployment/
├── README.md (this file)
│
├── packitty/
│   ├── README.md
│   ├── ubuntu/
│   │   ├── README.md
│   │   └── deploy.sh
│   ├── aws/
│   │   ├── README.md
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── terraform.tfvars.example
│   │   └── deploy.sh
│   └── scripts/
│       ├── README.md
│       ├── attack.sh
│       ├── quick-attack.sh
│       ├── restart-app.sh
│       ├── get-ec2-ip.sh
│       └── run-with-sudo.sh
│
└── k3s-flask-app/
    ├── README.md
    ├── app/
    │   ├── Dockerfile
    │   ├── main.py
    │   └── requirements.txt
    ├── envoy/
    │   └── envoy.yaml
    └── k8s/
        └── manifest.yaml
```

---

## Quick Start

### Deploy Packitty DDoS Detection

**Local Testing:**
```bash
sudo bash deployment/packitty/ubuntu/deploy.sh
curl http://localhost:8888
```

**AWS Production:**
```bash
cd deployment/packitty/aws
terraform init
terraform apply
```

### Deploy k3s Flask App

**Build & Deploy:**
```bash
cd deployment/k3s-flask-app
docker build -t packitty/app:v1 app/
kubectl apply -f k8s/manifest.yaml
curl http://127.0.0.1:30080/
```

---

## Project Separation

These are two **independent projects** in this repository:

1. **Packitty DDoS Detection** - Production security tool
   - Detects 8 types of DDoS attacks
   - Real-time packet capture and analysis
   - Production-ready deployment scripts

2. **k3s Flask App** - Kubernetes demo application
   - Simple Flask web service
   - Envoy proxy sidecar pattern
   - Educational Kubernetes example

They do **NOT** depend on each other and can be deployed independently.

---

## Environment Setup

Create `.env` files for each project (both git-ignored):

**Packitty:**
```bash
cat > deployment/packitty/.env << EOF
AWS_REGION=us-east-1
PACKITTY_INTERFACE=eth0
PACKITTY_PORT=8888
EOF
```

**k3s Flask App:**
```bash
cat > deployment/k3s-flask-app/.env << EOF
FLASK_ENV=production
FLASK_DEBUG=0
EOF
```

---

## Documentation

- **Packitty Main**: `../README.md`
- **Packitty Deployment**: `packitty/README.md`
- **Packitty Architecture**: `../Docs/architecture.md`
- **k3s Flask App**: `k3s-flask-app/README.md`

---

## Support

For issues with:
- **Packitty DDoS Detection**: See `packitty/README.md` troubleshooting section
- **k3s Flask App**: See `k3s-flask-app/README.md` troubleshooting section
