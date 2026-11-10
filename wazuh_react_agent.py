import os
import re
import json
import requests
import urllib3
from typing import Dict, Any

# Suppress insecure request warnings for self-signed Wazuh certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration & Credentials ---
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your_openai_api_key_or_ollama_key")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1") # Change for Ollama/LMStudio

# --- Wazuh API Integration ---
class WazuhClient:
    def __init__(self, base_url: str, user: str, pswd: str):
        self.base_url = base_url.rstrip('/')
        self.user = user
        self.pswd = pswd
        self.token = self._get_token()

    def _get_token(self) -> str:
        """Authenticates with the Wazuh API and retrieves a JWT token."""
        url = f"{self.base_url}/security/user/authenticate"
        response = requests.get(url, auth=(self.user, self.pswd), verify=False, timeout=10)
        response.raise_for_status()
        return response.json()['data']['token']

    def _request(self, endpoint: str) -> Dict:
        """Helper to make authenticated GET requests to the Wazuh API."""
        headers = {'Authorization': f'Bearer {self.token}'}
        url = f"{self.base_url}{endpoint}"
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        # Handle token expiration (simplified for triage script)
        if response.status_code == 401:
            self.token = self._get_token()
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(url, headers=headers, verify=False, timeout=10)
        return response.json()

    def get_agent_info(self, agent_id: str) -> str:
        """Retrieves details about a specific Wazuh agent."""
        try:
            res = self._request(f"/agents?agent_list={agent_id}")
            if not res['data']['affected_items']:
                return f"Agent {agent_id} not found."
            agent = res['data']['affected_items'][0]
            return json.dumps({
                "id": agent.get("id"),
                "name": agent.get("name"),
                "status": agent.get("status"),
                "os": agent.get("os", {}).get("name"),
                "ip": agent.get("ip")
            })
        except Exception as e:
            return f"Error retrieving agent info: {str(e)}"

    def get_rule_details(self, rule_id: str) -> str:
        """Retrieves MITRE tactics and descriptions for a Wazuh rule."""
        try:
            res = self._request(f"/rules?rule_ids={rule_id}")
            if not res['data']['affected_items']:
                return f"Rule {rule_id} not found."
            rule = res['data']['affected_items'][0]
            return json.dumps({
                "description": rule.get("description"),
                "level": rule.get("level"),
                "mitre": rule.get("mitre", {}).get("id", []),
                "groups": rule.get("groups", [])
            })
        except Exception as e:
            return f"Error retrieving rule details: {str(e)}"

# --- ReAct Agent Core ---
class SecurityReActAgent:
    def __init__(self, wazuh_client: WazuhClient):
        self.wazuh = wazuh_client
        
        # Define available tools for the LLM
        self.tools = {
            "get_agent_info": self.wazuh.get_agent_info,
            "get_rule_details": self.wazuh.get_rule_details
        }
        
        self.system_prompt = """You are a highly capable SOC Analyst AI Assistant.
You have access to a Wazuh SIEM API. Your goal is to triage security alerts by gathering context.

You operate in a strict Reason-and-Act (ReAct) loop.
You must ALWAYS use the following format:

Thought: you should always think about what to do next
Action: the action to take, exactly matching one of: [get_agent_info, get_rule_details]
Action Input: the input to the action (e.g., "001" for agent_id, or "100201" for rule_id)
Observation: the result of the action (provided by the system)
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now have enough information to form a triage summary.
Final Answer: The final triage report for the analyst.

Tools available:
- get_agent_info: Takes an agent_id (e.g. "005"). Returns the OS, IP, and connection status.
- get_rule_details: Takes a Wazuh rule_id (e.g. "5501"). Returns description, severity level, and MITRE mapping.

Begin!"""

    def _call_llm(self, messages: list) -> str:
        """Makes a request to an OpenAI-compatible API (OpenAI, Ollama, LMStudio)."""
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "gpt-4", # Or "llama3" if using local Ollama
            "messages": messages,
            "temperature": 0.1,
            "stop": ["Observation:"] # Crucial: Force LLM to stop generating when it expects an observation
        }
        response = requests.post(f"{OPENAI_BASE_URL}/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content'].strip()

    def run(self, alert_context: str, max_steps: int = 8) -> str:
        """Executes the ReAct loop to triage an alert."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Triage this new Wazuh alert: {alert_context}"}
        ]
        
        print(f"\n[*] Starting AI Triage for alert context: {alert_context}\n")
        
        for step in range(max_steps):
            print(f"[Step {step+1}] Reasoning...")
            response_text = self._call_llm(messages)
            print(response_text)
            
            # Check if the LLM arrived at a final conclusion
            if "Final Answer:" in response_text:
                return response_text.split("Final Answer:")[-1].strip()
            
            # Extract Action and Action Input using Regex
            action_match = re.search(r"Action:\s*(\w+)", response_text)
            input_match = re.search(r"Action Input:\s*(.+)", response_text)
            
            if not action_match or not input_match:
                # LLM broke format, gently push it back
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": "Observation: Format error. Please use 'Action: <tool>' and 'Action Input: <arg>'."})
                continue
                
            action_name = action_match.group(1).strip()
            action_input = input_match.group(1).strip().strip('"').strip("'")
            
            # Execute the tool
            if action_name in self.tools:
                print(f"[*] Executing Tool: {action_name}({action_input})")
                observation = self.tools[action_name](action_input)
            else:
                observation = f"Tool '{action_name}' does not exist."
                
            print(f"[*] Observation: {observation}\n")
            
            # Append interaction to chat history for the next loop iteration
            messages.append({"role": "assistant", "content": response_text})
            messages.append({"role": "user", "content": f"Observation: {observation}"})
            
        return "Triage failed: Maximum reasoning steps reached without a Final Answer."

if __name__ == "__main__":
    # Initialize the Wazuh connection
    try:
        wazuh = WazuhClient(WAZUH_API_URL, WAZUH_USER, WAZUH_PASSWORD)
        print("[+] Successfully connected to Wazuh API")
    except Exception as e:
        print(f"[-] Failed to connect to Wazuh API: {e}")
        exit(1)

    # Initialize ReAct Agent
    agent = SecurityReActAgent(wazuh)

    # Example Incident passed to the agent from a SIEM trigger
    # In a real environment, this string comes from a webhook or Elasticsearch query
    mock_incident_trigger = "Alert triggered on agent '002' for Rule ID '5710' (sshd: Attempt to login using a non-existent user)."
    
    # Run the triage loop
    final_report = agent.run(mock_incident_trigger)
    
    print("\n" + "="*60)
    print("FINAL TRIAGE REPORT:")
    print("="*60)
    print(final_report)