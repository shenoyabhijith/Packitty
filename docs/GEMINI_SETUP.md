# Gemini AI Agent Setup Guide

This guide explains how to use the LiteLLM-powered Gemini AI agent for intelligent DDoS mitigation.

## Overview

The DDoS Shield system includes an AI-powered agent that uses **LiteLLM** with **Google Gemini** to make intelligent mitigation decisions. The agent analyzes attack patterns, system context, and provides recommendations for optimal mitigation strategies.

## Prerequisites

1. **Python 3.8+**
2. **LiteLLM** installed (already in requirements.txt)
3. **Gemini API Key** (provided or from Google AI Studio)

## Installation

### 1. Install Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

This will install:
- `litellm` - Unified LLM interface
- All other dependencies

### 2. Configure Gemini API Key

The API key is loaded from a `.env` file:

#### Create .env File

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env

# Or create it manually
cat > .env << EOF
GEMINI_API_KEY=AIzaSyAwX6QqNqG3mLVjntknChi-i_s8X6vBNIg
USE_AI_AGENT=true
EOF
```

The `.env` file is already created with your API key. You can update it if needed.

#### Get Your Own Key (Optional)
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Update the `GEMINI_API_KEY` value in `.env` file

## Configuration

### Enable/Disable AI Agent

Control whether to use the AI agent via environment variable:

```bash
# Enable AI agent (default)
export USE_AI_AGENT=true

# Disable AI agent (use rule-based only)
export USE_AI_AGENT=false
```

## Usage

### Starting the Application

```bash
source venv/bin/activate
python app.py
```

The system will:
1. Try to initialize the LiteLLM Gemini agent
2. If successful, use AI for mitigation decisions
3. If failed, fall back to rule-based logic

### How It Works

1. **Attack Detection**: ML model detects an attack
2. **Context Gathering**: System collects:
   - Attack details (type, severity, confidence)
   - Recent attack patterns
   - System statistics
3. **AI Analysis**: Gemini analyzes the context via LiteLLM and recommends:
   - **BLOCK**: Immediately block the source IP
   - **RATE_LIMIT**: Throttle traffic from source IP
   - **MONITOR**: Continue monitoring without action
4. **Mitigation Execution**: System executes the recommended action

### AI Agent Features

The AI agent considers:
- **Attack Type**: SYN Flood, HTTP Flood, UDP Flood, Slowloris, DNS Amplification
- **Severity**: HIGH, MEDIUM, LOW
- **Confidence**: ML model confidence score
- **System Load**: Current traffic volume and resource usage
- **Attack Patterns**: Recent attack history and trends
- **Risk Assessment**: False positive probability

## Example AI Decision

When an attack is detected, the Gemini AI agent might respond:

```json
{
    "action": "BLOCK",
    "reasoning": "High confidence SYN Flood attack with 95% confidence. System is under moderate load. Immediate blocking recommended to prevent service degradation.",
    "confidence": 0.92,
    "additional_recommendations": [
        "Monitor system resources for 5 minutes",
        "Review logs for similar patterns",
        "Consider rate limiting if false positives occur"
    ]
}
```

## Gemini Models Available

The system uses `gemini/gemini-1.5-pro` by default. You can change it in `ai_agent.py`:

- `gemini/gemini-1.5-pro` - Most capable (default)
- `gemini/gemini-1.5-flash` - Faster, lower cost
- `gemini/gemini-pro` - Previous generation

## Fallback Behavior

If the AI agent is not available or fails:
- System automatically falls back to rule-based logic
- No service interruption
- Logs indicate which method was used

## Troubleshooting

### Issue: "litellm not installed"
**Solution**: 
```bash
pip install litellm
```

### Issue: "Failed to initialize LiteLLM"
**Possible causes**:
1. Invalid API key
2. Network connectivity issues
3. API rate limits

**Solutions**:
1. Verify API key is correct
2. Check internet connectivity
3. Wait and retry if rate limited

### Issue: "AI agent error, falling back to rule-based"
**Solution**: Check logs for specific error. Common issues:
- Invalid API key
- Network timeout
- API quota exceeded

## Cost Considerations

- Gemini API pricing: Pay per request
- Typical cost: ~$0.0001-0.001 per mitigation decision
- Very cost-effective compared to other LLM providers
- Free tier available from Google

## Advanced Configuration

### Custom Agent Configuration

Edit `ai_agent.py` to customize:
- Model selection (pro vs flash)
- Prompt engineering
- Decision thresholds
- Additional context gathering

### Debug Mode

Enable verbose logging in `ai_agent.py`:
```python
litellm.set_verbose = True  # Shows detailed API calls
```

## Monitoring

Check logs for:
- `AI Agent Decision:` - Shows AI recommendations
- `AI Reasoning:` - Explains the decision
- `AI Mitigation Explanation:` - Full analysis

## API Key Security

**Important**: The API key is stored in `.env` file:
1. ✅ Already using `.env` file (not hardcoded)
2. ⚠️ Make sure `.env` is in `.gitignore` (never commit to git)
3. 🔄 Rotate keys regularly
4. 🔒 For production, consider using a secure vault service

**Note**: The `.env` file is already created with your API key. Keep it secure and never share it publicly.

## Support

For issues with:
- **LiteLLM**: https://docs.litellm.ai
- **Gemini API**: https://ai.google.dev
- **This Integration**: Check logs and fallback behavior

