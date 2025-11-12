"""
AI Agent Module for DDoS Mitigation using LiteLLM with Gemini
This module provides intelligent decision-making for attack mitigation
"""

import logging
from typing import Dict, List, Optional
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# Try to import litellm, fallback to mock if not available
try:
    import litellm
    from litellm import completion
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False
    logger.warning("litellm not installed. Using fallback decision logic.")
    logger.warning("Install with: pip install litellm")

# Gemini API Key - Load from .env file
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY not found in .env file. AI agent will not work.")
    logger.error("Please create a .env file with: GEMINI_API_KEY=your-api-key")


class DDoSAIAgent:
    """
    AI Agent for intelligent DDoS mitigation decisions using LiteLLM with Gemini
    """
    
    def __init__(self, use_ai: bool = True, api_key: str = None):
        """
        Initialize the AI Agent
        
        Args:
            use_ai: Whether to use AI agent or fallback logic
            api_key: Gemini API key (defaults to environment variable or provided key)
        """
        self.use_ai = use_ai and LITELLM_AVAILABLE
        self.api_key = api_key or GEMINI_API_KEY
        
        if self.use_ai:
            try:
                # Configure LiteLLM for Gemini
                os.environ['GEMINI_API_KEY'] = self.api_key
                litellm.set_verbose = False  # Set to True for debugging
                logger.info("LiteLLM with Gemini initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize LiteLLM: {e}")
                logger.info("Falling back to rule-based mitigation")
                self.use_ai = False
        else:
            logger.info("Using rule-based mitigation (AI agent not available)")
    
    def analyze_attack_context(self, alert: Dict, recent_alerts: List[Dict], 
                               system_stats: Dict) -> Dict:
        """
        Analyze attack context and provide intelligent mitigation recommendation
        
        Args:
            alert: Current alert information
            recent_alerts: Recent alerts for pattern analysis
            system_stats: Current system statistics
            
        Returns:
            Dictionary with mitigation recommendation and reasoning
        """
        if self.use_ai:
            return self._ai_analyze(alert, recent_alerts, system_stats)
        else:
            return self._rule_based_analyze(alert, recent_alerts, system_stats)
    
    def _ai_analyze(self, alert: Dict, recent_alerts: List[Dict], 
                    system_stats: Dict) -> Dict:
        """
        Use LiteLLM with Gemini to analyze and recommend mitigation strategy
        Uses tool calling to execute UFW blocking commands
        """
        try:
            # Import UFW tools
            from ufw_tools import block_ip_with_ufw, rate_limit_ip_with_ufw
            
            # Prepare context for the AI agent
            context = self._prepare_context(alert, recent_alerts, system_stats)
            source_ip = alert['source_ip']
            
            # Create prompt for the AI agent with tool calling
            prompt = f"""You are a cybersecurity expert analyzing a DDoS attack. 

Attack Details:
- Type: {alert['attack_type']}
- Source IP: {alert['source_ip']}
- Severity: {alert['severity']}
- Confidence: {alert['confidence']:.2%}
- Packet Rate: {alert['features']['packet_rate']:.0f} packets/sec
- Byte Rate: {alert['features']['byte_rate']:.0f} bytes/sec
- Connection Rate: {alert['features']['connection_rate']:.0f} connections/sec

System Context:
- Total Requests: {system_stats.get('total_requests', 0)}
- Threats Detected: {system_stats.get('threats_detected', 0)}
- Blocked IPs: {system_stats.get('blocked_ips', 0)}
- Recent Alerts: {len(recent_alerts)} in last period

Based on this information, decide the best mitigation strategy and execute it:
1. If you decide to BLOCK: Call the block_ip_with_ufw tool with the source IP
2. If you decide to RATE_LIMIT: Call the rate_limit_ip_with_ufw tool with the source IP
3. If you decide to MONITOR: Do not call any tools, just respond with your reasoning

Consider:
- Attack severity and type
- System load and capacity
- Pattern of recent attacks
- Risk of false positives"""
            
            # Define tools for LiteLLM
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "block_ip_with_ufw",
                        "description": "Block an IP address using UFW firewall. Use this for high-severity attacks that need immediate blocking.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_ip": {
                                    "type": "string",
                                    "description": f"The IP address to block. Current attack source: {source_ip}"
                                }
                            },
                            "required": ["source_ip"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "rate_limit_ip_with_ufw",
                        "description": "Rate limit an IP address using UFW firewall. Use this for moderate threats that need throttling.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_ip": {
                                    "type": "string",
                                    "description": f"The IP address to rate limit. Current attack source: {source_ip}"
                                }
                            },
                            "required": ["source_ip"]
                        }
                    }
                }
            ]
            
            # Query Gemini via LiteLLM with tool calling
            response = completion(
                model="gemini/gemini-2.5-flash",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in DDoS attack mitigation. Analyze attacks and use the provided tools to block or rate limit IPs when necessary."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                tools=tools,
                tool_choice="auto",  # Let the model decide when to use tools
                api_key=self.api_key
            )
            
            # Check if AI called a tool
            message = response.choices[0].message
            tool_calls = getattr(message, 'tool_calls', None) or []
            
            action = 'MONITOR'
            reasoning = 'AI analysis completed'
            tool_executed = False
            
            # Process tool calls
            if tool_calls and len(tool_calls) > 0:
                for tool_call in tool_calls:
                    try:
                        function_name = tool_call.function.name
                        function_args_str = tool_call.function.arguments
                        
                        # Parse function arguments
                        if isinstance(function_args_str, str):
                            function_args = json.loads(function_args_str)
                        else:
                            function_args = function_args_str
                        
                        if function_name == 'block_ip_with_ufw':
                            from ufw_tools import block_ip_with_ufw
                            target_ip = function_args.get('source_ip', alert['source_ip'])
                            result = block_ip_with_ufw(target_ip)
                            action = 'BLOCK'
                            ufw_command = result.get('command', f'sudo ufw deny from {target_ip}')
                            if result.get('simulated', False):
                                ufw_command = f"{ufw_command} (SIMULATED)"
                            else:
                                ufw_command = f"{ufw_command} (EXECUTED)"
                            
                            # Enhanced reasoning with attack type and detailed explanation
                            attack_type = alert.get('attack_type', 'Unknown')
                            severity = alert.get('severity', 'Unknown')
                            confidence = alert.get('confidence', 0.0)
                            # Handle both dict and list formats for features
                            features = alert.get('features', {})
                            if isinstance(features, dict):
                                packet_rate = features.get('packet_rate', 0)
                            elif isinstance(features, list) and len(features) > 0:
                                packet_rate = features[0]
                            else:
                                packet_rate = 0
                            
                            reasoning = f"AI detected {attack_type} attack from {target_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                            reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                            reasoning += f"Decision: Immediate BLOCK action required due to high-severity {attack_type} attack pattern. "
                            reasoning += f"UFW result: {result.get('message', 'Command executed')}"
                            
                            tool_executed = True
                            logger.info(f"AI executed BLOCK tool for {target_ip}: {result.get('message')}")
                            
                        elif function_name == 'rate_limit_ip_with_ufw':
                            from ufw_tools import rate_limit_ip_with_ufw
                            target_ip = function_args.get('source_ip', alert['source_ip'])
                            result = rate_limit_ip_with_ufw(target_ip)
                            action = 'RATE_LIMIT'
                            ufw_command = result.get('command', f'sudo ufw limit from {target_ip}')
                            if result.get('simulated', False):
                                ufw_command = f"{ufw_command} (SIMULATED)"
                            else:
                                ufw_command = f"{ufw_command} (EXECUTED)"
                            
                            # Enhanced reasoning with attack type and detailed explanation
                            attack_type = alert.get('attack_type', 'Unknown')
                            severity = alert.get('severity', 'Unknown')
                            confidence = alert.get('confidence', 0.0)
                            # Handle both dict and list formats for features
                            features = alert.get('features', {})
                            if isinstance(features, dict):
                                packet_rate = features.get('packet_rate', 0)
                            elif isinstance(features, list) and len(features) > 0:
                                packet_rate = features[0]
                            else:
                                packet_rate = 0
                            
                            reasoning = f"AI detected {attack_type} attack from {target_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                            reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                            reasoning += f"Decision: RATE_LIMIT action applied to throttle {attack_type} attack while preserving legitimate connections. "
                            reasoning += f"UFW result: {result.get('message', 'Command executed')}"
                            
                            tool_executed = True
                            logger.info(f"AI executed RATE_LIMIT tool for {target_ip}: {result.get('message')}")
                    except Exception as e:
                        logger.error(f"Error processing tool call: {e}")
                        continue
            
            # If no tool was called, parse the response
            if not tool_executed:
                ai_response = message.content.strip() if hasattr(message, 'content') and message.content else ""
                
                # Get attack details for enhanced reasoning
                attack_type = alert.get('attack_type', 'Unknown')
                severity = alert.get('severity', 'Unknown')
                confidence = alert.get('confidence', 0.0)
                source_ip = alert.get('source_ip', 'Unknown')
                # Handle both dict and list formats for features
                features = alert.get('features', {})
                if isinstance(features, dict):
                    packet_rate = features.get('packet_rate', 0)
                elif isinstance(features, list) and len(features) > 0:
                    packet_rate = features[0]
                else:
                    packet_rate = 0
                
                # Try to extract JSON from response
                try:
                    import re
                    if ai_response:
                        json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                        if json_match:
                            result = json.loads(json_match.group())
                            action = result.get('action', 'MONITOR')
                            base_reasoning = result.get('reasoning', 'AI analysis completed')
                            # Enhance with attack type details
                            reasoning = f"AI detected {attack_type} attack from {source_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                            reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                            reasoning += f"Decision: {base_reasoning}"
                        else:
                            # Parse text response
                            result = self._parse_text_response(ai_response)
                            action = result['action']
                            base_reasoning = result['reasoning']
                            # Enhance with attack type details
                            reasoning = f"AI detected {attack_type} attack from {source_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                            reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                            reasoning += f"Decision: {base_reasoning}"
                    else:
                        reasoning = f"AI detected {attack_type} attack from {source_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                        reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                        reasoning += "Decision: Monitoring recommended - threat level not sufficient for immediate action."
                except Exception as e:
                    logger.error(f"Error parsing AI response: {e}")
                    reasoning = f"AI detected {attack_type} attack from {source_ip} (Severity: {severity}, Confidence: {confidence:.1%}). "
                    reasoning += f"Attack characteristics: {packet_rate:.0f} packets/sec. "
                    reasoning += f"Decision: {ai_response if ai_response else 'Monitoring recommended - threat level not sufficient for immediate action.'}"
            
            recommendation = {
                'action': action,
                'reasoning': reasoning,
                'confidence': 0.9 if tool_executed else 0.7,
                'additional_recommendations': [],
                'tool_executed': tool_executed
            }
            
            # Add UFW command if tool was executed
            if tool_executed and 'ufw_command' in locals():
                recommendation['ufw_command'] = ufw_command
            
            return recommendation
                
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            logger.info("Falling back to rule-based mitigation")
            return self._rule_based_analyze(alert, recent_alerts, system_stats)
    
    def _parse_text_response(self, response: str) -> Dict:
        """
        Parse text response from AI agent into structured format
        """
        response_lower = response.lower()
        
        # Determine action from keywords
        if 'block' in response_lower or 'deny' in response_lower:
            action = 'BLOCK'
        elif 'rate limit' in response_lower or 'throttle' in response_lower:
            action = 'RATE_LIMIT'
        else:
            action = 'MONITOR'
        
        return {
            'action': action,
            'reasoning': response[:200],  # First 200 chars
            'confidence': 0.7,
            'additional_recommendations': []
        }
    
    def _prepare_context(self, alert: Dict, recent_alerts: List[Dict], 
                        system_stats: Dict) -> str:
        """Prepare context string for AI agent"""
        context_parts = [
            f"Current Attack: {alert['attack_type']} from {alert['source_ip']}",
            f"Severity: {alert['severity']}, Confidence: {alert['confidence']:.2%}",
            f"System Load: {system_stats.get('total_requests', 0)} total requests",
            f"Recent Attacks: {len(recent_alerts)} in monitoring window"
        ]
        return "\n".join(context_parts)
    
    def _rule_based_analyze(self, alert: Dict, recent_alerts: List[Dict], 
                           system_stats: Dict) -> Dict:
        """
        Fallback rule-based analysis when AI is not available
        """
        attack_type = alert['attack_type']
        severity = alert['severity']
        confidence = alert['confidence']
        
        # Rule-based decision logic
        if severity == 'HIGH' or attack_type in ['SYN_Flood', 'HTTP_Flood', 'DNS_Amplification']:
            action = 'BLOCK'
            reasoning = f"High severity {attack_type} attack detected. Immediate blocking recommended."
        elif attack_type == 'UDP_Flood' and confidence > 0.9:
            action = 'BLOCK'
            reasoning = "High confidence UDP Flood attack. Blocking source IP."
        elif attack_type == 'Slowloris':
            action = 'RATE_LIMIT'
            reasoning = "Slowloris attack detected. Rate limiting to preserve connections."
        elif len(recent_alerts) > 5:
            action = 'BLOCK'
            reasoning = "Multiple attacks detected. Blocking to prevent escalation."
        else:
            action = 'RATE_LIMIT'
            reasoning = "Moderate threat. Rate limiting to mitigate impact."
        
        return {
            'action': action,
            'reasoning': reasoning,
            'confidence': 0.8,
            'additional_recommendations': [
                "Monitor system resources",
                "Review attack patterns in logs"
            ]
        }
    
    def get_mitigation_command(self, action: str, source_ip: str) -> str:
        """
        Generate firewall command based on action
        
        Args:
            action: Mitigation action (BLOCK, RATE_LIMIT, MONITOR)
            source_ip: Source IP address to mitigate
            
        Returns:
            Firewall command string
        """
        if action == 'BLOCK':
            return f"sudo ufw deny from {source_ip}"
        elif action == 'RATE_LIMIT':
            return f"sudo ufw limit from {source_ip}"
        else:  # MONITOR
            return f"# Monitor {source_ip} - no action taken"
    
    def explain_decision(self, alert: Dict, recommendation: Dict) -> str:
        """
        Generate human-readable explanation of mitigation decision
        """
        return f"""
Mitigation Decision for {alert['attack_type']} Attack:
- Action: {recommendation['action']}
- Reasoning: {recommendation.get('reasoning', 'No reasoning provided')}
- Confidence: {recommendation.get('confidence', 0.0):.1%}
- Source IP: {alert['source_ip']}

Additional Recommendations:
{chr(10).join('- ' + rec for rec in recommendation.get('additional_recommendations', []))}
"""


# Global AI agent instance
_ai_agent_instance = None

def get_ai_agent(use_ai: bool = True, api_key: str = None) -> DDoSAIAgent:
    """
    Get or create the global AI agent instance
    
    Args:
        use_ai: Whether to use AI agent
        api_key: Gemini API key (optional, uses default if not provided)
        
    Returns:
        DDoSAIAgent instance
    """
    global _ai_agent_instance
    if _ai_agent_instance is None:
        _ai_agent_instance = DDoSAIAgent(use_ai=use_ai, api_key=api_key)
    return _ai_agent_instance

