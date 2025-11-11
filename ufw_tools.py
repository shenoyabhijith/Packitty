"""
UFW Firewall Tools for AI Agent
Provides tools that the AI agent can call to block IPs using UFW
"""

import subprocess
import logging
import os

logger = logging.getLogger(__name__)

# Safety flag - set to True to enable actual UFW commands
ENABLE_UFW_EXECUTION = os.getenv('ENABLE_UFW_EXECUTION', 'false').lower() == 'true'

def block_ip_with_ufw(source_ip: str) -> dict:
    """
    Block an IP address using UFW firewall
    
    Args:
        source_ip: IP address to block
        
    Returns:
        Dictionary with success status and message
    """
    if not ENABLE_UFW_EXECUTION:
        logger.warning(f"UFW execution disabled. Would block IP: {source_ip}")
        return {
            'success': True,
            'action': 'BLOCK',
            'ip': source_ip,
            'command': f'sudo ufw deny from {source_ip}',
            'message': f'IP {source_ip} would be blocked (UFW execution disabled)',
            'simulated': True
        }
    
    try:
        # Execute UFW deny command
        command = ['sudo', 'ufw', 'deny', 'from', source_ip]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked IP {source_ip} using UFW")
            return {
                'success': True,
                'action': 'BLOCK',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'IP {source_ip} has been blocked',
                'output': result.stdout,
                'simulated': False
            }
        else:
            logger.error(f"Failed to block IP {source_ip}: {result.stderr}")
            return {
                'success': False,
                'action': 'BLOCK',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'Failed to block IP {source_ip}',
                'error': result.stderr,
                'simulated': False
            }
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout while blocking IP {source_ip}")
        return {
            'success': False,
            'action': 'BLOCK',
            'ip': source_ip,
            'message': f'Timeout while blocking IP {source_ip}',
            'simulated': False
        }
    except Exception as e:
        logger.error(f"Error blocking IP {source_ip}: {e}")
        return {
            'success': False,
            'action': 'BLOCK',
            'ip': source_ip,
            'message': f'Error blocking IP {source_ip}: {str(e)}',
            'simulated': False
        }

def rate_limit_ip_with_ufw(source_ip: str) -> dict:
    """
    Rate limit an IP address using UFW firewall
    
    Args:
        source_ip: IP address to rate limit
        
    Returns:
        Dictionary with success status and message
    """
    if not ENABLE_UFW_EXECUTION:
        logger.warning(f"UFW execution disabled. Would rate limit IP: {source_ip}")
        return {
            'success': True,
            'action': 'RATE_LIMIT',
            'ip': source_ip,
            'command': f'sudo ufw limit from {source_ip}',
            'message': f'IP {source_ip} would be rate limited (UFW execution disabled)',
            'simulated': True
        }
    
    try:
        # Execute UFW limit command
        command = ['sudo', 'ufw', 'limit', 'from', source_ip]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully rate limited IP {source_ip} using UFW")
            return {
                'success': True,
                'action': 'RATE_LIMIT',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'IP {source_ip} has been rate limited',
                'output': result.stdout,
                'simulated': False
            }
        else:
            logger.error(f"Failed to rate limit IP {source_ip}: {result.stderr}")
            return {
                'success': False,
                'action': 'RATE_LIMIT',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'Failed to rate limit IP {source_ip}',
                'error': result.stderr,
                'simulated': False
            }
    except Exception as e:
        logger.error(f"Error rate limiting IP {source_ip}: {e}")
        return {
            'success': False,
            'action': 'RATE_LIMIT',
            'ip': source_ip,
            'message': f'Error rate limiting IP {source_ip}: {str(e)}',
            'simulated': False
        }

def unblock_ip_with_ufw(source_ip: str) -> dict:
    """
    Unblock an IP address using UFW firewall
    
    Args:
        source_ip: IP address to unblock
        
    Returns:
        Dictionary with success status and message
    """
    if not ENABLE_UFW_EXECUTION:
        logger.warning(f"UFW execution disabled. Would unblock IP: {source_ip}")
        return {
            'success': True,
            'action': 'UNBLOCK',
            'ip': source_ip,
            'command': f'sudo ufw delete deny from {source_ip}',
            'message': f'IP {source_ip} would be unblocked (UFW execution disabled)',
            'simulated': True
        }
    
    try:
        # Execute UFW delete deny command
        command = ['sudo', 'ufw', 'delete', 'deny', 'from', source_ip]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully unblocked IP {source_ip} using UFW")
            return {
                'success': True,
                'action': 'UNBLOCK',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'IP {source_ip} has been unblocked',
                'output': result.stdout,
                'simulated': False
            }
        else:
            logger.error(f"Failed to unblock IP {source_ip}: {result.stderr}")
            return {
                'success': False,
                'action': 'UNBLOCK',
                'ip': source_ip,
                'command': ' '.join(command),
                'message': f'Failed to unblock IP {source_ip}',
                'error': result.stderr,
                'simulated': False
            }
    except Exception as e:
        logger.error(f"Error unblocking IP {source_ip}: {e}")
        return {
            'success': False,
            'action': 'UNBLOCK',
            'ip': source_ip,
            'message': f'Error unblocking IP {source_ip}: {str(e)}',
            'simulated': False
        }

