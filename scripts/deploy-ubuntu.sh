#!/bin/bash
################################################################################
# Packitty DDoS Detection - Ubuntu Server Deployment Script
# 
# This script handles complete deployment on Ubuntu:
# 1. Backs up existing deployment
# 2. Installs system dependencies
# 3. Sets up Python virtual environment
# 4. Installs Python dependencies
# 5. Configures application
# 6. Starts the application
#
# Usage: sudo bash deploy-ubuntu.sh
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_DIR="/opt/packitty"
BACKUP_DIR="/opt/packitty-backup-$(date +%Y%m%d-%H%M%S)"
APP_PORT=8888
APP_USER="ubuntu"

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_ubuntu() {
    if [ ! -f /etc/os-release ]; then
        log_error "Not running on a supported Linux distribution"
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu. Detected: $ID"
    fi
}

################################################################################
# Main Deployment Steps
################################################################################

main() {
    log_section "🚀 Packitty DDoS Detection - Ubuntu Deployment"
    
    check_root
    check_ubuntu
    
    # Step 1: Backup existing deployment
    log_section "Step 1: Backup Existing Deployment"
    if [ -d "$DEPLOY_DIR" ]; then
        log_info "Backing up existing deployment to $BACKUP_DIR"
        cp -r "$DEPLOY_DIR" "$BACKUP_DIR"
        log_info "✅ Backup complete"
    else
        log_info "No existing deployment found"
    fi
    
    # Step 2: Clean deployment directory (only if empty or if explicitly requested)
    log_section "Step 2: Prepare Deployment Directory"
    # Change to a safe directory before checking deployment dir
    cd /tmp || cd /root || cd /home/ubuntu || true
    
    # If directory exists and has files, skip removal (files were just copied)
    if [ -d "$DEPLOY_DIR" ] && [ -n "$(ls -A "$DEPLOY_DIR" 2>/dev/null)" ]; then
        log_info "Deployment directory already contains files, skipping cleanup"
        log_info "Files will be updated in place"
    else
        if [ -d "$DEPLOY_DIR" ]; then
            log_info "Removing old empty deployment folder"
            rm -rf "$DEPLOY_DIR"
        fi
        log_info "Creating deployment directory"
        mkdir -p "$DEPLOY_DIR"
    fi
    log_info "✅ Directory prepared"
    
    # Step 3: System dependencies
    log_section "Step 3: Install System Dependencies"
    log_info "Updating package lists..."
    apt-get update -qq
    
    log_info "Installing required packages..."
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-venv \
        git \
        curl \
        wget \
        net-tools \
        tcpdump \
        libpcap-dev \
        libffi-dev \
        libssl-dev \
        > /dev/null 2>&1
    
    log_info "✅ System dependencies installed"
    
    # Step 4: Verify Python and install pip if needed
    log_section "Step 4: Verify Python Environment"
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 not found"
        exit 1
    fi
    
    python3_version=$(python3 --version)
    log_info "Python version: $python3_version"
    
    # Check if pip is available, install if not
    if ! python3 -m pip --version &> /dev/null; then
        log_info "pip not found, installing..."
        # Change to a safe directory before installing
        cd /tmp || cd /root || cd /home/ubuntu || true
        apt-get install -y python3-pip --quiet
    fi
    
    # Verify pip works (from safe directory)
    cd /tmp || cd /root || cd /home/ubuntu || true
    python3 -m pip --version
    log_info "✅ Python environment ready"
    
    # Step 5: Setup Application Code
    log_section "Step 5: Setup Application Code"
    if [ ! -d "$DEPLOY_DIR" ]; then
        log_error "Deployment directory not found: $DEPLOY_DIR"
        log_info "Files should have been copied to this location"
        exit 1
    fi
    
    # Ensure we're in the deployment directory
    cd "$DEPLOY_DIR" || {
        log_error "Failed to change to deployment directory: $DEPLOY_DIR"
        exit 1
    }
    
    # Verify key files exist
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found in $DEPLOY_DIR"
        log_info "Contents of $DEPLOY_DIR:"
        ls -la "$DEPLOY_DIR" | head -20
        exit 1
    fi
    
    log_info "✅ Application code ready"
    
    # Step 6: Setup Python Virtual Environment
    log_section "Step 6: Setup Python Virtual Environment"
    cd "$DEPLOY_DIR" || {
        log_error "Failed to change to deployment directory: $DEPLOY_DIR"
        exit 1
    }
    
    log_info "Creating Python virtual environment..."
    python3 -m venv venv || {
        log_error "Failed to create virtual environment"
        exit 1
    }
    
    log_info "Activating virtual environment and installing dependencies..."
    source venv/bin/activate
    python3 -m pip install --upgrade pip --quiet
    python3 -m pip install -r requirements.txt --quiet
    
    log_info "✅ Python dependencies installed"
    
    # Step 7: Configure application
    log_section "Step 7: Configure Application"
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        log_info "Creating .env configuration..."
        cat > .env << 'EOF'
# Packitty Configuration
HOST=0.0.0.0
PORT=8888
DEBUG=False
LOG_LEVEL=INFO
INTERFACE=eth0
SECRET_KEY=packitty-production-secret-$(date +%s)
EOF
        log_info "✅ Created .env file (edit as needed)"
    fi
    
    # Create logs directory
    mkdir -p logs
    log_info "✅ Logs directory ready"
    
    # Step 8: Setup systemd service
    log_section "Step 8: Create Systemd Service"
    
    log_info "Creating packitty.service..."
    cat > /etc/systemd/system/packitty.service << EOF
[Unit]
Description=Packitty DDoS Detection System
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$DEPLOY_DIR
EnvironmentFile=$DEPLOY_DIR/.env
ExecStart=$DEPLOY_DIR/venv/bin/python app.py
Restart=on-failure
RestartSec=5s
StandardOutput=append:$DEPLOY_DIR/logs/systemd.log
StandardError=append:$DEPLOY_DIR/logs/systemd-error.log
# Packet capture requires elevated privileges
# To run without root, configure sudo or use capabilities

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 /etc/systemd/system/packitty.service
    systemctl daemon-reload
    log_info "✅ Systemd service created"
    
    # Step 9: Setup firewall rules
    log_section "Step 9: Configure Firewall"
    
    if command -v ufw &> /dev/null; then
        log_info "Configuring UFW firewall..."
        ufw allow 8888/tcp || true
        log_info "✅ Port 8888 allowed"
    else
        log_info "UFW not found, skipping firewall configuration"
    fi
    
    # Step 10: Start application
    log_section "Step 10: Start Application"
    
    log_info "Starting Packitty service..."
    systemctl start packitty
    
    sleep 2
    
    if systemctl is-active --quiet packitty; then
        log_info "✅ Packitty service is running"
    else
        log_error "Failed to start Packitty service"
        log_info "Check logs with: journalctl -u packitty -n 50"
        exit 1
    fi
    
    # Enable on boot
    systemctl enable packitty
    log_info "✅ Packitty enabled to start on boot"
    
    # Final status
    log_section "🎉 Deployment Complete!"
    
    echo -e "${GREEN}Service Status:${NC}"
    systemctl status packitty --no-pager
    
    echo -e "\n${GREEN}Next Steps:${NC}"
    echo "  1. Access dashboard: http://$(hostname -I | awk '{print $1}'):$APP_PORT"
    echo "  2. Check logs: tail -f $DEPLOY_DIR/logs/systemd.log"
    echo "  3. Manage service:"
    echo "     - sudo systemctl stop packitty"
    echo "     - sudo systemctl restart packitty"
    echo "     - sudo systemctl status packitty"
    echo ""
    echo -e "${GREEN}Configuration:${NC}"
    echo "  - App directory: $DEPLOY_DIR"
    echo "  - Config file: $DEPLOY_DIR/.env"
    echo "  - Logs: $DEPLOY_DIR/logs/"
    echo ""
    echo -e "${GREEN}Backup Info:${NC}"
    echo "  - Previous deployment backed up to: $BACKUP_DIR"
    echo ""
}

# Error handler
trap 'log_error "Deployment failed at line $LINENO"; exit 1' ERR

# Run main function
main

