#!/bin/bash
################################################################################
# Packitty DDoS Detection - Ubuntu Server Deployment Script
# 
# This script handles complete deployment on Ubuntu:
# 1. Backs up existing deployment
# 2. Installs system dependencies
# 3. Sets up uv package manager
# 4. Installs Python dependencies
# 5. Configures application
# 6. Starts the application
#
# Usage: sudo bash deploy.sh
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
REPO_URL="https://github.com/shenoyabhijith/Packitty.git"
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
    
    # Step 2: Clean deployment directory
    log_section "Step 2: Clean Deployment Directory"
    if [ -d "$DEPLOY_DIR" ]; then
        log_info "Removing old deployment folder"
        rm -rf "$DEPLOY_DIR"
    fi
    log_info "Creating fresh deployment directory"
    mkdir -p "$DEPLOY_DIR"
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
    
    # Step 4: Install uv package manager
    log_section "Step 4: Install uv Package Manager"
    if ! command -v uv &> /dev/null; then
        log_info "Installing uv package manager..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="/root/.local/bin:$PATH"
        log_info "✅ uv installed"
    else
        log_info "uv already installed"
        uv --version
    fi
    
    # Step 5: Clone/Update repository
    log_section "Step 5: Setup Application Code"
    if [ -d "$DEPLOY_DIR/.git" ]; then
        log_info "Updating existing repository..."
        cd "$DEPLOY_DIR"
        git pull origin main
    else
        log_info "Cloning repository..."
        cd /opt
        git clone "$REPO_URL" packitty || {
            log_error "Failed to clone repository"
            log_info "You may need to configure git credentials"
            exit 1
        }
    fi
    
    cd "$DEPLOY_DIR"
    log_info "✅ Application code ready"
    
    # Step 6: Install Python dependencies
    log_section "Step 6: Install Python Dependencies"
    cd "$DEPLOY_DIR/DeepPacketInspection"
    
    log_info "Installing uv dependencies..."
    /root/.local/bin/uv pip install -r requirements.txt --quiet
    
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
WorkingDirectory=$DEPLOY_DIR/DeepPacketInspection
EnvironmentFile=$DEPLOY_DIR/DeepPacketInspection/.env
ExecStart=/root/.local/bin/uv run python app.py
Restart=on-failure
RestartSec=5s
StandardOutput=append:$DEPLOY_DIR/DeepPacketInspection/logs/systemd.log
StandardError=append:$DEPLOY_DIR/DeepPacketInspection/logs/systemd-error.log
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
    echo "  2. Check logs: tail -f $DEPLOY_DIR/DeepPacketInspection/logs/packet_inspector.log"
    echo "  3. Manage service:"
    echo "     - sudo systemctl stop packitty"
    echo "     - sudo systemctl restart packitty"
    echo "     - sudo systemctl status packitty"
    echo ""
    echo -e "${GREEN}Configuration:${NC}"
    echo "  - App directory: $DEPLOY_DIR"
    echo "  - Config file: $DEPLOY_DIR/DeepPacketInspection/.env"
    echo "  - Logs: $DEPLOY_DIR/DeepPacketInspection/logs/"
    echo ""
    echo -e "${GREEN}Backup Info:${NC}"
    echo "  - Previous deployment backed up to: $BACKUP_DIR"
    echo ""
}

# Error handler
trap 'log_error "Deployment failed at line $LINENO"; exit 1' ERR

# Run main function
main

