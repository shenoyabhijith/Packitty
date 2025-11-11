# Ubuntu Server Deployment

Deploy Packitty DDoS Detection on Ubuntu with a single command.

## Quick Start

```bash
sudo bash deployment/packitty/ubuntu/deploy.sh
```

## What It Does

The deployment script automates:

1. **Backup** - Creates timestamped backup of existing deployment
2. **Clean** - Removes old deployment folder
3. **Dependencies** - Installs system packages (build-essential, python3-dev, libpcap-dev, etc.)
4. **uv** - Installs uv package manager
5. **Code** - Clones/updates application from repository
6. **Python** - Installs all Python dependencies
7. **Config** - Creates .env configuration file
8. **Service** - Sets up systemd service for auto-start
9. **Firewall** - Configures UFW firewall rules
10. **Start** - Starts application automatically

## System Requirements

- **OS**: Ubuntu 20.04, 22.04, or 24.04
- **RAM**: Minimum 1GB
- **Disk**: 10GB free space
- **Access**: sudo/root privileges
- **Network**: Internet access for package installation

## Deployment Directory

After deployment, files are located at:

- **Application**: `/opt/packitty`
- **Backup**: `/opt/packitty-backup-YYYYMMDD-HHMMSS`
- **Logs**: `/opt/packitty/DeepPacketInspection/logs/`
- **Config**: `/opt/packitty/DeepPacketInspection/.env`

## Post-Deployment

### Access Application

Dashboard: `http://your-server-ip:8888`

### Service Management

```bash
# Check status
sudo systemctl status packitty

# Start service
sudo systemctl start packitty

# Stop service
sudo systemctl stop packitty

# Restart service
sudo systemctl restart packitty

# View logs
sudo journalctl -u packitty -f

# View recent errors
sudo journalctl -u packitty -n 100
```

### Check Logs

```bash
# Application logs
tail -f /opt/packitty/DeepPacketInspection/logs/packet_inspector.log

# Error logs
tail -f /opt/packitty/DeepPacketInspection/logs/errors.log

# All logs
ls -la /opt/packitty/DeepPacketInspection/logs/
```

## Configuration

### Edit Configuration

```bash
# Edit application config
sudo nano /opt/packitty/DeepPacketInspection/config.py

# Edit environment variables
sudo nano /opt/packitty/DeepPacketInspection/.env
```

### Network Interface

To specify a different network interface:

```bash
# Find available interfaces
ip addr

# Update config.py
DEFAULT_INTERFACE = 'eth0'  # or your interface name
```

### Ports

Default configuration:
- **Dashboard**: Port 8888
- **Network Interface**: eth0 (configurable)

## Firewall Rules

The script automatically configures UFW:

```bash
# Allow port 8888
sudo ufw allow 8888/tcp

# Check rules
sudo ufw status numbered
```

## Troubleshooting

### Service Won't Start

```bash
# Check detailed error
sudo systemctl status packitty -l

# View recent logs
sudo journalctl -u packitty -n 50

# Try running manually
cd /opt/packitty/DeepPacketInspection
sudo /root/.local/bin/uv run python app.py
```

### Permission Denied

```bash
# Ensure running with sudo
sudo bash deployment/packitty/ubuntu/deploy.sh

# Check permissions
ls -la /opt/packitty
```

### Port Already in Use

```bash
# Find process using port 8888
sudo lsof -i :8888

# Kill the process
sudo kill <PID>

# Or change port in config.py
PORT = 9999
```

### No Packets Captured

```bash
# Check available interfaces
ip addr

# Verify interface name
cat /opt/packitty/DeepPacketInspection/config.py | grep DEFAULT_INTERFACE

# Restart service
sudo systemctl restart packitty

# Check logs
tail -f /opt/packitty/DeepPacketInspection/logs/packet_inspector.log
```

### uv Installation Issues

```bash
# Check if uv is installed
which uv

# Manual installation
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH
export PATH="/root/.local/bin:$PATH"
```

## Update Deployment

To update to latest code:

```bash
cd /opt/packitty
sudo git pull origin main
sudo systemctl restart packitty
```

## Remove Deployment

To completely remove:

```bash
# Stop service
sudo systemctl stop packitty
sudo systemctl disable packitty

# Remove systemd service
sudo rm /etc/systemd/system/packitty.service
sudo systemctl daemon-reload

# Remove application
sudo rm -rf /opt/packitty

# Remove backups (optional)
sudo rm -rf /opt/packitty-backup-*
```

## Backup & Recovery

### Manual Backup

```bash
sudo tar -czf packitty-backup-$(date +%Y%m%d-%H%M%S).tar.gz /opt/packitty
```

### Restore from Backup

```bash
sudo systemctl stop packitty
sudo rm -rf /opt/packitty
sudo tar -xzf packitty-backup-YYYYMMDD-HHMMSS.tar.gz -C /
sudo systemctl start packitty
```

## Performance Tuning

### Increase Capture Timeout

Edit `/opt/packitty/DeepPacketInspection/config.py`:

```python
CAPTURE_TIMEOUT = 30  # Increase timeout
```

### Adjust Thresholds

```python
VOLUMETRIC_PPS_THRESHOLD = 500
BANDWIDTH_BPS_THRESHOLD = 1_000_000
# ... other thresholds
```

## Security Recommendations

1. **Firewall**: Use UFW/iptables to restrict access
2. **Updates**: Keep Ubuntu packages updated
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
3. **Monitoring**: Monitor disk space for logs
4. **Backups**: Regular backups of `/opt/packitty`
5. **Access Control**: Restrict SSH access

## Monitoring

### Check System Resources

```bash
# CPU and memory usage
top

# Disk usage
df -h

# Network interface stats
ifstat

# Process info
ps aux | grep packitty
```

### View Dashboard

Open in browser: `http://your-server-ip:8888`

The dashboard shows:
- Real-time attack statistics
- Top attacking IPs
- Attack types detected
- Packets per second
- Traffic breakdown

## Next Steps

1. Access dashboard: `http://your-server-ip:8888`
2. Configure for your network interface
3. Run attack simulation: `./deployment/packitty/scripts/attack.sh volumetric 60 medium`
4. Monitor logs in real-time
5. Set up backups and monitoring

## Support

For issues or questions:
1. Check logs: `sudo journalctl -u packitty -f`
2. See troubleshooting section above
3. Review Docs: `../../README.md`
4. Check architecture: `../../../Docs/architecture.md`

