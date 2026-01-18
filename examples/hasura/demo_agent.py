#!/usr/bin/env python3
"""
Demo script showing how an AI agent uses Vouch with Hasura.

Prerequisites:
1. Run: docker-compose up  (starts Hasura + Vouch webhook)
2. Run: python demo_agent.py

This script simulates an AI agent making authenticated GraphQL requests.
"""

import os
import json
import requests

from vouch import Signer
from vouch.keys import generate_ed25519_keypair


def main():
    # -------------------------------------------------------------------------
    # Step 1: Generate or load agent credentials
    # -------------------------------------------------------------------------
    print("🔑 Generating agent credentials...")

    private_key, public_key = generate_ed25519_keypair()
    agent_did = "did:web:demo-agent.vouch-protocol.com"

    signer = Signer(private_key=private_key, did=agent_did)

    print(f"   Agent DID: {agent_did}")
    print(f"   Public Key: {public_key[:50]}...")

    # -------------------------------------------------------------------------
    # Step 2: Sign a GraphQL query with intent
    # -------------------------------------------------------------------------
    print("\n✍️  Signing GraphQL request with Vouch...")

    intent = {
        "action": "query_users",
        "query": "{ users { id name email } }",
        "reason": "Fetching user list for daily report",
    }

    # Include reputation score (affects role assignment)
    vouch_token = signer.sign(intent, reputation_score=75)

    print(f"   Intent: {intent['action']}")
    print(f"   Token: {vouch_token[:50]}...")

    # -------------------------------------------------------------------------
    # Step 3: Make authenticated request to Hasura
    # -------------------------------------------------------------------------
    print("\n📡 Making authenticated request to Hasura...")

    hasura_url = os.getenv("HASURA_URL", "http://localhost:8080/v1/graphql")

    headers = {
        "Content-Type": "application/json",
        "Vouch-Token": vouch_token,
    }

    payload = {"query": intent["query"]}

    try:
        response = requests.post(hasura_url, headers=headers, json=payload, timeout=5)

        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")

        if response.status_code == 200:
            print("\n✅ SUCCESS! Agent authenticated and query executed.")
        else:
            print("\n❌ Request failed (this is expected if Hasura isn't running)")
            print("   Run 'docker-compose up' first to start the demo environment.")

    except requests.exceptions.ConnectionError:
        print("\n⚠️  Could not connect to Hasura.")
        print("   Run 'docker-compose up' first to start the demo environment.")

    # -------------------------------------------------------------------------
    # Step 4: Show what the webhook would see
    # -------------------------------------------------------------------------
    print("\n📋 What the Vouch webhook verifies:")
    print(f"   • Agent DID (identity): {agent_did}")
    print(f"   • Intent: {intent['action']}")
    print(f"   • Reputation: 75 → Role: agent_writer")
    print("   • Signature: Ed25519 (cryptographically verified)")


if __name__ == "__main__":
    main()
