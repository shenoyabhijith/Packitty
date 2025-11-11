# Packitty EC2 Deployment Guide

This guide explains how to deploy the Packitty DDoS Detection application to an EC2 instance.

## Prerequisites

1. **EC2 Instance**: You need an EC2 instance running Ubuntu
2. **SSH Access**: You need SSH access to the EC2 instance
3. **SSH Key**: The private key file (`id_rsa`) should be in the project root directory

## Deployment Options

### Option 1: Deploy to Existing EC2 Instance

If you already have an EC2 instance running:

```bash
# Deploy with EC2 IP as parameter
bash scripts/deploy-to-ec2.sh <EC2_IP_ADDRESS>

# Or let the script try to get IP from Terraform
bash scripts/deploy-to-ec2.sh
```

### Option 2: Deploy Infrastructure First

If you need to create the EC2 instance first:

1. **Configure Terraform variables:**
   ```bash
   cd infrastructure
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your VPC and Subnet IDs
   ```

2. **Deploy infrastructure:**
   ```bash
   bash infrastructure/deploy.sh
   ```

3. **Deploy application:**
   ```bash
   cd ..
   bash scripts/deploy-to-ec2.sh
   ```

## What the Deployment Does

The deployment script (`deploy-to-ec2.sh`) will:

1. **Get EC2 IP**: From Terraform output or user input
2. **Test SSH Connection**: Verify connectivity to EC2
3. **Copy Files**: Transfer application code to EC2 (excluding venv, logs, etc.)
4. **Deploy**: Run the deployment script on EC2 which:
   - Installs system dependencies
   - Creates Python virtual environment
   - Installs Python packages
   - Configures the application
   - Sets up systemd service
   - Starts the application

## After Deployment

Once deployed, you can:

- **Access Dashboard**: `http://<EC2_IP>:8888`
- **Check Service Status**: 
  ```bash
  ssh -i id_rsa ubuntu@<EC2_IP> 'sudo systemctl status packitty'
  ```
- **View Logs**:
  ```bash
  ssh -i id_rsa ubuntu@<EC2_IP> 'tail -f /opt/packitty/logs/systemd.log'
  ```
- **Restart Service**:
  ```bash
  ssh -i id_rsa ubuntu@<EC2_IP> 'sudo systemctl restart packitty'
  ```

## Troubleshooting

### SSH Connection Failed
- Verify EC2 instance is running
- Check security group allows SSH (port 22)
- Ensure SSH key permissions: `chmod 600 id_rsa`
- Verify the correct IP address

### Deployment Fails on EC2
- Check EC2 logs: `ssh -i id_rsa ubuntu@<EC2_IP> 'sudo journalctl -u packitty -n 50'`
- Verify system dependencies are installed
- Check Python version (requires Python 3.6+)

### Application Not Accessible
- Verify security group allows port 8888
- Check if service is running: `sudo systemctl status packitty`
- Check firewall rules: `sudo ufw status`

## Files Deployed

The following files are copied to EC2:
- `app.py` - Main Flask application
- `ai_agent.py` - AI agent module
- `requirements.txt` - Python dependencies
- `ddos_model.pkl` - Trained ML model
- `feature_names.pkl` - Feature names for model
- `ufw_tools.py` - UFW firewall tools
- `scripts/` - Deployment scripts
- Other application files

Excluded files:
- `venv/` - Virtual environment (created on EC2)
- `__pycache__/` - Python cache
- `*.log` - Log files
- `infrastructure/` - Terraform files
- `.git/` - Git repository

