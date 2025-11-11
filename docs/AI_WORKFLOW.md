# AI Agent Workflow with UFW Tool Calling

## Overview

The DDoS Shield system now includes an AI-powered workflow that uses **LiteLLM with Gemini** to analyze attacks and automatically execute UFW firewall commands to block malicious IPs.

## How It Works

### 1. Attack Detection
- ML model detects an attack from a **random private IP** (10.x.x.x, 172.16-31.x.x, or 192.168.x.x)
- Attack is validated to reduce false positives
- Alert is created with attack details

### 2. AI Agent Analysis
- Gemini AI agent receives:
  - Attack type, severity, confidence
  - Source IP address (private IP)
  - System statistics
  - Recent attack patterns
- AI analyzes the threat and decides on mitigation

### 3. Tool Calling
The AI agent can call two tools:

#### `block_ip_with_ufw(source_ip)`
- **When to use**: High-severity attacks (SYN Flood, HTTP Flood, DNS Amplification)
- **Action**: Blocks the IP using `sudo ufw deny from <ip>`
- **Result**: IP is immediately blocked

#### `rate_limit_ip_with_ufw(source_ip)`
- **When to use**: Moderate threats (UDP Flood, Slowloris)
- **Action**: Rate limits the IP using `sudo ufw limit from <ip>`
- **Result**: IP traffic is throttled

### 4. Execution
- If AI calls a tool → UFW command is executed immediately
- If AI recommends MONITOR → No action taken
- All actions are logged with AI reasoning

## Private IP Generation

All simulated attacks use **random private IP addresses**:
- **10.0.0.0/8**: `10.x.x.x` (Class A private)
- **172.16.0.0/12**: `172.16-31.x.x` (Class B private)
- **192.168.0.0/16**: `192.168.x.x` (Class C private)

This allows safe testing without affecting real public IPs.

## Configuration

### Enable UFW Execution

By default, UFW commands are **simulated** (not executed). To enable actual blocking:

1. Edit `.env` file:
```bash
ENABLE_UFW_EXECUTION=true
```

2. **WARNING**: This will execute real UFW commands!
   - Make sure you have sudo access
   - Only enable in safe test environments
   - Test with private IPs first

### Enable AI Agent

```bash
USE_AI_AGENT=true  # Already enabled by default
```

## Workflow Example

1. **User clicks "SYN FLOOD" button**
   - System generates attack traffic
   - Random private IP: `192.168.45.123`
   - ML model detects SYN Flood attack

2. **AI Agent analyzes**
   - Gemini receives attack context
   - AI decides: "High severity SYN Flood, immediate blocking required"
   - AI calls `block_ip_with_ufw("192.168.45.123")`

3. **UFW Tool executes**
   - Command: `sudo ufw deny from 192.168.45.123`
   - IP is blocked (or simulated if disabled)
   - Result logged

4. **UI updates**
   - Alert shows "AI Powered" badge
   - AI reasoning displayed
   - IP appears in blocked list

## Testing

### Test with Simulated UFW (Safe)
```bash
# .env
ENABLE_UFW_EXECUTION=false  # Default
```

1. Start the app
2. Click any attack button
3. Watch AI agent analyze and "block" IPs
4. Check logs for AI decisions

### Test with Real UFW (Requires sudo)
```bash
# .env
ENABLE_UFW_EXECUTION=true
```

1. Make sure you have sudo access
2. Start the app
3. Click attack button
4. AI will actually block the private IP
5. Verify with: `sudo ufw status | grep <ip>`

## Files

- `ai_agent.py` - AI agent with tool calling
- `ufw_tools.py` - UFW blocking tools
- `app.py` - Main application with private IP generation
- `.env` - Configuration (API key, UFW enable flag)

## Safety Features

1. **Private IPs only** - Attacks use private IP ranges
2. **UFW disabled by default** - Commands are simulated
3. **Explicit enable flag** - Must set `ENABLE_UFW_EXECUTION=true`
4. **Error handling** - Falls back to rule-based if AI fails
5. **Logging** - All actions are logged

## Unblocking IPs

If you need to unblock an IP:

```bash
sudo ufw delete deny from <ip>
```

Or use the unblock tool:
```python
from ufw_tools import unblock_ip_with_ufw
result = unblock_ip_with_ufw("192.168.1.100")
```

## Monitoring

Check AI agent activity:
- **Logs**: Look for "AI executed BLOCK tool" or "AI executed RATE_LIMIT tool"
- **UI**: "AI Powered" badge on alerts
- **Stats**: "AI-Powered" stat card shows count

## Troubleshooting

### AI not calling tools
- Check Gemini API key in `.env`
- Verify `USE_AI_AGENT=true`
- Check logs for AI errors

### UFW commands not executing
- Verify `ENABLE_UFW_EXECUTION=true` in `.env`
- Check sudo permissions
- Verify UFW is installed: `which ufw`

### Private IPs not generating
- Check `generate_private_ip()` function
- Verify random module is imported

