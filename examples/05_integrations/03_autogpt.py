#!/usr/bin/env python3
"""
03_autogpt.py - Vouch with AutoGPT

Add cryptographic signing to AutoGPT plugins.

Run: python 03_autogpt.py
"""

from vouch import Signer

print("🤖 AutoGPT + Vouch")
print("=" * 50)

# =============================================================================
# AutoGPT Plugin Style
# =============================================================================

print("""
# In your AutoGPT plugin:

from vouch import Signer
from vouch.integrations.autogpt import VouchPlugin

class MyPlugin(VouchPlugin):
    def __init__(self):
        super().__init__()
        self.signer = Signer(name="AutoGPT Agent")
    
    def execute_command(self, command: str, args: dict):
        # Sign the command before execution
        token = self.signer.sign({
            "command": command,
            "args": args,
            "timestamp": datetime.now().isoformat()
        })
        
        # Execute with signed intent
        result = self._do_command(command, args)
        
        # Log signed action
        self.log_signed_action(token, result)
        
        return result
""")

# =============================================================================
# Demonstration
# =============================================================================

signer = Signer(name="AutoGPT Plugin")

# Simulate a plugin command
command = "file_write"
args = {"path": "/data/report.txt", "content": "Analysis results..."}

import json
payload = json.dumps({"command": command, "args": args})
token = signer.sign(payload)

print("\n📋 Signed Command:")
print(f"   Command: {command}")
print(f"   Args: {args}")
print(f"   Token: {token[:60]}...")

print("""
✅ Benefits for AutoGPT:
   • Every file write is signed
   • API calls are attributable  
   • Memory operations are logged
   • Full audit trail
""")
