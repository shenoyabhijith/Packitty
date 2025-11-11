#!/bin/bash
################################################################################
# Packitty DDoS Detection - EC2 Deployment Script
# 
# This script deploys the code to an EC2 instance:
# 1. Gets EC2 IP from Terraform or accepts as parameter
# 2. Copies code to EC2 via SCP
# 3. Runs deployment script on EC2
#
# Usage: 
#   bash scripts/deploy-to-ec2.sh [EC2_IP]
#   bash scripts/deploy-to-ec2.sh  # Will try to get IP from Terraform
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH_USER="ubuntu"
SSH_KEY="${PROJECT_ROOT}/id_rsa"
DEPLOY_SCRIPT="${PROJECT_ROOT}/scripts/deploy-ubuntu.sh"

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}\n"
}

################################################################################
# Get EC2 IP
################################################################################

get_ec2_ip() {
    local ip="$1"
    
    # If IP provided as argument, use it
    if [ -n "$ip" ]; then
        echo "$ip"
        return 0
    fi
    
    # Try to get from Terraform
    if [ -f "${PROJECT_ROOT}/infrastructure/terraform.tfstate" ]; then
        log_info "Getting EC2 IP from Terraform..."
        cd "${PROJECT_ROOT}/infrastructure"
        terraform_ip=$(terraform output -raw instance_public_ip 2>/dev/null || echo "")
        if [ -n "$terraform_ip" ]; then
            echo "$terraform_ip"
            return 0
        fi
    fi
    
    # Prompt user
    log_error "Could not determine EC2 IP automatically"
    echo -e "${YELLOW}Please provide the EC2 instance public IP:${NC}"
    read -r ec2_ip
    echo "$ec2_ip"
}

################################################################################
# Check Prerequisites
################################################################################

check_prerequisites() {
    log_section "Checking Prerequisites"
    
    # Check SSH key - try root directory first
    if [ ! -f "$SSH_KEY" ]; then
        # Try alternative locations
        if [ -f "${PROJECT_ROOT}/../id_rsa" ]; then
            SSH_KEY="${PROJECT_ROOT}/../id_rsa"
            log_info "Using SSH key from parent directory"
        elif [ -f "$HOME/.ssh/id_rsa" ]; then
            SSH_KEY="$HOME/.ssh/id_rsa"
            log_info "Using SSH key from ~/.ssh/"
        else
            log_error "SSH key not found: $SSH_KEY"
            log_info "Please ensure you have the SSH private key (id_rsa) in the project root"
            log_info "Or deploy infrastructure first to generate keys"
            exit 1
        fi
    fi
    
    # Set correct permissions for SSH key
    chmod 600 "$SSH_KEY" 2>/dev/null || true
    log_info "Using SSH key: $SSH_KEY"
    
    # Check if SSH is available
    if ! command -v ssh &> /dev/null; then
        log_error "SSH client not found"
        exit 1
    fi
    
    # Check if SCP is available
    if ! command -v scp &> /dev/null; then
        log_error "SCP not found"
        exit 1
    fi
    
    log_info "✅ Prerequisites check passed"
}

################################################################################
# Test SSH Connection
################################################################################

test_ssh_connection() {
    local ec2_ip="$1"
    
    log_section "Testing SSH Connection"
    
    log_info "Testing connection to $ec2_ip..."
    if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           "${SSH_USER}@${ec2_ip}" "echo 'Connection successful'" &>/dev/null; then
        log_info "✅ SSH connection successful"
        return 0
    else
        log_error "Failed to connect to EC2 instance"
        log_info "Please verify:"
        log_info "  1. EC2 instance is running"
        log_info "  2. Security group allows SSH (port 22)"
        log_info "  3. SSH key is correct"
        log_info "  4. Instance public IP is correct"
        exit 1
    fi
}

################################################################################
# Copy Files to EC2
################################################################################

copy_files_to_ec2() {
    local ec2_ip="$1"
    
    log_section "Copying Files to EC2"
    
    # Create temporary directory for files to copy
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT
    
    log_info "Preparing files for deployment..."
    
    # Copy application files using tar+ssh for better compatibility
    log_info "Creating deployment archive..."
    cd "$PROJECT_ROOT"
    # Create tar archive with all necessary files
    tar --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='.git' \
        --exclude='.env' \
        --exclude='*.log' \
        --exclude='infrastructure' \
        --exclude='.terraform' \
        --exclude='terraform.tfstate*' \
        --exclude='id_rsa*' \
        --exclude='.DS_Store' \
        -czf "$TEMP_DIR/packitty-deploy.tar.gz" .
    
    log_info "Copying files to EC2..."
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$TEMP_DIR/packitty-deploy.tar.gz" \
        "${SSH_USER}@${ec2_ip}:/tmp/packitty-deploy.tar.gz"
    
    log_info "Extracting files on EC2..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${ec2_ip}" << 'ENDEXTRACT'
        set -e
        mkdir -p /tmp/packitty-deploy
        if [ ! -f "/tmp/packitty-deploy.tar.gz" ]; then
            echo "ERROR: Archive not found"
            exit 1
        fi
        # Extract tar - it may create a subdirectory, so handle both cases
        cd /tmp/packitty-deploy
        tar -xzf /tmp/packitty-deploy.tar.gz
        rm /tmp/packitty-deploy.tar.gz
        
        # If tar created a subdirectory (like latest_packitty_code), move contents up
        if [ -d "latest_packitty_code" ]; then
            mv latest_packitty_code/* . 2>/dev/null || true
            mv latest_packitty_code/.[!.]* . 2>/dev/null || true
            rmdir latest_packitty_code 2>/dev/null || true
        fi
        
        echo "Files extracted. Contents:"
        ls -la /tmp/packitty-deploy | head -10
        if [ -f "/tmp/packitty-deploy/requirements.txt" ]; then
            echo "✓ requirements.txt found"
        else
            echo "✗ requirements.txt NOT found"
            echo "Looking for requirements.txt:"
            find /tmp/packitty-deploy -name "requirements.txt" -type f 2>/dev/null || echo "Not found anywhere"
        fi
ENDEXTRACT
    
    log_info "✅ Files copied to EC2"
}

################################################################################
# Deploy on EC2
################################################################################

deploy_on_ec2() {
    local ec2_ip="$1"
    
    log_section "Deploying Application on EC2"
    
    log_info "Running deployment script on EC2..."
    
    # Copy deployment script and run it
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${ec2_ip}" << 'ENDSSH'
        set -e
        
        # Verify files were extracted
        if [ ! -d "/tmp/packitty-deploy" ] || [ -z "$(ls -A /tmp/packitty-deploy 2>/dev/null)" ]; then
            echo "ERROR: Files not found in /tmp/packitty-deploy"
            ls -la /tmp/ | grep packitty || true
            exit 1
        fi
        
        # Backup existing deployment if it exists (deployment script will handle this, but we need files first)
        if [ -d "/opt/packitty" ] && [ "$(ls -A /opt/packitty 2>/dev/null)" ]; then
            echo "Backing up existing deployment..."
            sudo cp -r /opt/packitty "/opt/packitty-backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
        fi
        
        # Move files to deployment location - copy to temp first, then move
        sudo mkdir -p /opt/packitty-temp
        sudo rm -rf /opt/packitty-temp/*
        
        # Copy all files including hidden ones
        sudo cp -r /tmp/packitty-deploy/. /opt/packitty-temp/ 2>&1
        sudo chown -R ubuntu:ubuntu /opt/packitty-temp
        
        # Verify files are there
        if [ ! -f "/opt/packitty-temp/requirements.txt" ]; then
            echo "ERROR: requirements.txt not found after copy to temp"
            ls -la /opt/packitty-temp | head -20
            exit 1
        fi
        
        # Now move to final location (deployment script expects /opt/packitty)
        sudo rm -rf /opt/packitty
        sudo mv /opt/packitty-temp /opt/packitty
        sudo chown -R ubuntu:ubuntu /opt/packitty
        
        # Make deployment script executable
        sudo chmod +x /opt/packitty/scripts/deploy-ubuntu.sh
        
        # Run deployment script from safe directory
        cd /tmp
        sudo bash /opt/packitty/scripts/deploy-ubuntu.sh
ENDSSH
    
    log_info "✅ Deployment completed on EC2"
}

################################################################################
# Main Function
################################################################################

main() {
    log_section "🚀 Packitty DDoS Detection - EC2 Deployment"
    
    # Get EC2 IP
    EC2_IP=$(get_ec2_ip "$1")
    
    if [ -z "$EC2_IP" ]; then
        log_error "EC2 IP is required"
        exit 1
    fi
    
    log_info "Target EC2 IP: $EC2_IP"
    
    # Check prerequisites
    check_prerequisites
    
    # Test SSH connection
    test_ssh_connection "$EC2_IP"
    
    # Copy files
    copy_files_to_ec2 "$EC2_IP"
    
    # Deploy on EC2
    deploy_on_ec2 "$EC2_IP"
    
    # Final status
    log_section "🎉 Deployment Complete!"
    
    echo -e "${GREEN}Application deployed successfully!${NC}"
    echo -e "\n${GREEN}Access the dashboard:${NC}"
    echo "  http://${EC2_IP}:8888"
    echo -e "\n${GREEN}Check service status:${NC}"
    echo "  ssh -i $SSH_KEY ${SSH_USER}@${EC2_IP} 'sudo systemctl status packitty'"
    echo -e "\n${GREEN}View logs:${NC}"
    echo "  ssh -i $SSH_KEY ${SSH_USER}@${EC2_IP} 'tail -f /opt/packitty/logs/systemd.log'"
}

# Error handler
trap 'log_error "Deployment failed at line $LINENO"; exit 1' ERR

# Run main function
main "$@"

