"""
Vouch Protocol: Hands-On Tutorial (v1.2.0)

This script demonstrates the core lifecycle of a "Vouched" interaction:
1. Identity Generation (The birth of an agent)
2. Signing (The agent expressing intent)
3. Verification (The receiver trusting the agent)
4. Reputation (Building trust over time)

Run this script to see the protocol in action!
"""

import asyncio
import json
import logging
import sys
from datetime import datetime

# Setup improved logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("tutorial")

# Import the protocol
try:
    from vouch import (
        Signer,
        Verifier,
        generate_identity,
        ReputationEngine,
        MemoryReputationStore
    )
except ImportError:
    print("❌ Vouch Protocol not found. Please install it:")
    print("   pip install vouch-protocol")
    sys.exit(1)


async def main():
    print("\n🚀 Welcome to Vouch Protocol v1.2.0 Interactive Tutorial\n")
    print("=======================================================")
    
    # ---------------------------------------------------------
    # STEP 1: IDENTITY
    # ---------------------------------------------------------
    print("\n[STEP 1] Generating Digital Identity...")
    print("---------------------------------------")
    
    # Generate a fresh keypair
    # In production, you would generate this once and store it securely (e.g. env vars or KMS)
    keys = generate_identity(domain="tutorial-agent.com")
    
    print(f"✅ Identity Created!")
    print(f"   DID (ID Card):    {keys.did}")
    print(f"   Public Key (Face): {json.loads(keys.public_key_jwk)['x'][:10]}... (Safe to share)")
    print(f"   Private Key:      [HIDDEN] (Never share this!)")
    
    # ---------------------------------------------------------
    # STEP 2: SIGNING
    # ---------------------------------------------------------
    print("\n\n[STEP 2] Agent Actions (Signing)...")
    print("-----------------------------------")
    
    # The agent wants to perform an action
    action = {
        "intent": "read_database",
        "target": "users_table",
        "query": "SELECT * FROM users LIMIT 5",
        "timestamp": datetime.now().isoformat()
    }
    print(f"🤖 Agent wants to: {action['intent']} on {action['target']}")
    
    # Initialize the Signer with the private key
    signer = Signer(
        private_key=keys.private_key_jwk,
        did=keys.did
    )
    
    # Sign the intent
    print("✍️  Signing the intent...")
    token = signer.sign(action)
    
    print(f"✅ Vouch Token Generated!")
    print(f"   Token length: {len(token)} chars")
    print(f"   Token preview: {token[:20]}...{token[-20:]}")
    print("   (This token is essentially a digital passport stamped with the action)")
    
    # ---------------------------------------------------------
    # STEP 3: VERIFICATION
    # ---------------------------------------------------------
    print("\n\n[STEP 3] The Gatekeeper (Verification)...")
    print("-----------------------------------------")
    
    print("🔒 Gatekeeper received the token. Verifying...")
    
    # The Gatekeeper needs the agent's Public Key to verify the signature.
    # In a real scenario, it would fetch this from "https://tutorial-agent.com/.well-known/did.json"
    # Here, we pass it directly for the demo.
    
    is_valid, passport = Verifier.verify(
        token, 
        public_key_jwk=keys.public_key_jwk
    )
    
    if is_valid:
        print("✅ VERIFIED! The signature is authentic.")
        print(f"   Who signed it? {passport.sub}")
        print(f"   What did they sign? {passport.payload}")
        print("   Checking for tampering... None detected.")
    else:
        print("❌ Verification Failed! Do not trust this request.")
        return

    # ---------------------------------------------------------
    # STEP 4: REPUTATION
    # ---------------------------------------------------------
    print("\n\n[STEP 4] Reputation (The Trust Score)...")
    print("----------------------------------------")
    
    # Initialize Reputation Engine (using in-memory store for tutorial)
    reputation = ReputationEngine(store=MemoryReputationStore())
    
    # Check initial score
    score = await reputation.get_score(keys.did)
    print(f"📊 Initial Reputation for {keys.did}:")
    print(f"   Score: {score.score}/100")
    print(f"   Tier:  {score.tier.upper()}")
    
    print("\nCompleting successful task...")
    await reputation.record_success(keys.did, "Successfully executed SQL query")
    
    score = await reputation.get_score(keys.did)
    print(f"📈 Updated Score: {score.score}/100 (+1)")
    
    print("\nOops! Agent made a mistake (failed task)...")
    await reputation.record_failure(keys.did, "Database timeout")
    
    score = await reputation.get_score(keys.did)
    print(f"📉 Updated Score: {score.score}/100 (-2)")
    
    print("\n\n✅ TUTORIAL COMPLETE!")
    print("You have successfully:")
    print("1. Created a cryptographic identity")
    print("2. Signed a payload (Intent + Identity)")
    print("3. Verified the signature")
    print("4. Tracked reputation over time")
    print("\nNext step: Try integrating Vouch into your own agent!")

if __name__ == "__main__":
    asyncio.run(main())
