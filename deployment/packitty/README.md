# Packitty DDoS Detection System - Deployment

High-performance DDoS attack detection deployment procedures and infrastructure-as-code.

## Deployment Options

### 1. Ubuntu Server Deployment (Single Server)

Quick deployment on any Ubuntu server with a single script.

```bash
sudo bash deployment/packitty/ubuntu/deploy.sh
```

See: `deployment/packitty/ubuntu/README.md`

**Features:**
- One-command deployment
- Automatic system dependency installation
- uv package manager setup
- Systemd service management
- UFW firewall configuration
- Complete logging

**Requirements:**
- Ubuntu 20.04, 22.04, or 24.04
- 1GB+ RAM, 10GB+ disk space
- sudo access

---

### 2. AWS Infrastructure Deployment (Terraform)

Deploy Packitty on AWS EC2 using Infrastructure-as-Code with Terraform.

```bash
cd deployment/packitty/aws
terraform init
terraform plan
terraform apply
```

See: `deployment/packitty/aws/README.md`

**Resources Created:**
- EC2 instance (configurable size)
- Security groups with attack simulation rules
- IAM role for SSM Session Manager
- Instance profile for secure access

**Features:**
- Reproducible infrastructure
- Easy scaling
- Cost estimation included
- SSM Session Manager access (no SSH keys needed)

---

### 3. Attack Simulation

Test Packitty with simulated DDoS attacks.

```bash
./deployment/packitty/scripts/attack.sh <type> <duration> <intensity>
```

See: `deployment/packitty/scripts/README.md`

**Supported Attacks:**
- volumetric (UDP flood)
- syn_flood (TCP SYN)
- http_flood (HTTP requests)
- icmp_flood (ICMP ping)
- port_scan (Port scanning)
- amplification (Small packets)
- bandwidth (Large packets)
- mixed (Multiple attacks)

---

## Directory Structure

```
deployment/packitty/
├── README.md (this file)
├── ubuntu/
│   ├── README.md
│   └── deploy.sh (main deployment script)
├── aws/
│   ├── README.md
│   ├── main.tf (AWS resources)
│   ├── variables.tf (input variables)
│   ├── outputs.tf (output values)
│   ├── terraform.tfvars.example
│   └── deploy.sh (convenience script)
└── scripts/
    ├── README.md
    ├── attack.sh (attack simulation)
    ├── quick-attack.sh (shorthand)
    ├── restart-app.sh
    ├── get-ec2-ip.sh
    └── run-with-sudo.sh
```

---

## Quick Start

### Local Testing
```bash
# Deploy locally
sudo bash deployment/packitty/ubuntu/deploy.sh

# Access dashboard
curl http://localhost:8888

# Run attack simulation (different terminal)
./deployment/packitty/scripts/attack.sh volumetric 60 medium
```

### AWS Production
```bash
# Configure AWS
cd deployment/packitty/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your VPC/Subnet IDs

# Deploy
terraform init
terraform plan
terraform apply

# Connect and start app
aws ssm start-session --target <instance-id>
cd /opt/packitty
sudo systemctl start packitty
```

---

## Post-Deployment

### Access Application
- **Local**: `http://localhost:8888`
- **AWS**: `http://<instance-public-ip>:8888`

### Check Service Status
```bash
# Ubuntu
sudo systemctl status packitty

# View logs
sudo journalctl -u packitty -f

# Manual start
sudo systemctl restart packitty
```

### Configure Application
- Config file: `/opt/packitty/DeepPacketInspection/config.py`
- Environment file: `/opt/packitty/DeepPacketInspection/.env`
- Logs: `/opt/packitty/DeepPacketInspection/logs/`

---

## Troubleshooting

### Permission Denied
```bash
# All deployment scripts require sudo
sudo bash deployment/packitty/ubuntu/deploy.sh
```

### Port Already in Use
```bash
sudo lsof -i :8888
sudo kill <PID>
```

### No Packets Captured
1. Check network interface: `ip addr`
2. Update `DEFAULT_INTERFACE` in config.py
3. Restart: `sudo systemctl restart packitty`

### Service Won't Start
```bash
# Check status
sudo systemctl status packitty

# View detailed logs
sudo journalctl -u packitty -n 100

# Check Python errors
cd /opt/packitty/DeepPacketInspection
sudo uv run python app.py
```

---

## Environment Variables

Create `.env` file in deployment directory (git-ignored):

```env
# AWS (for remote deployment)
AWS_REGION=us-east-1
AWS_VPC_ID=vpc-xxxxx
AWS_SUBNET_ID=subnet-xxxxx

# Application
PACKITTY_INTERFACE=en0
PACKITTY_PORT=8888
PACKITTY_LOG_LEVEL=INFO

# Optional
DEBUG=false
```

---

## Deployment Cleanup

### Remove Ubuntu Deployment
```bash
sudo systemctl stop packitty
sudo rm -rf /opt/packitty
sudo rm /etc/systemd/system/packitty.service
sudo systemctl daemon-reload
```

### Remove AWS Infrastructure
```bash
cd deployment/packitty/aws
terraform destroy
```

---

## Security Best Practices

1. **SSH Keys**: Keep private keys secure (git-ignored)
2. **Terraform State**: Never commit `.tfstate` files
3. **Credentials**: Use environment variables, not hardcoded
4. **Firewall**: Restrict inbound access in production
5. **Monitoring**: Enable CloudWatch for AWS deployments
6. **Backups**: Regular backups of `/opt/packitty` directory

---

## Support & Documentation

- **Main README**: `../../README.md`
- **Architecture**: `../../Docs/architecture.md`
- **Backend Design**: `../../Docs/backend.md`
- **Infrastructure**: `../../Docs/infrastructure.md`
- **Dependencies**: `../../Docs/dependencies.md`

---

## Version Info

- **Python**: 3.8+
- **Framework**: Flask 2.3.3
- **Scapy**: 2.5.0
- **Terraform**: >= 1.0
- **Ubuntu**: 20.04, 22.04, 24.04

