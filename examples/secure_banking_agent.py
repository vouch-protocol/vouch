#!/usr/bin/env python3
"""
Secure Banking Agent Example - Google ADK with Vouch Protection.

Demonstrates how to use VouchIntegrator with Google ADK to create a banking
agent where high-risk operations (transfers, payments) are automatically
flagged, signed, and logged to Google Cloud Logging.

This example shows:
1. Setting up RiskPolicy with custom rules
2. Protecting ADK tools with VouchIntegrator
3. Handling HIGH risk actions with proper logging
4. Using the vouch signature in downstream calls

Prerequisites:
    pip install vouch-protocol google-cloud-logging google-genai

Environment Variables:
    VOUCH_PRIVATE_KEY: JWK JSON string for signing
    VOUCH_DID: Agent DID (e.g., did:vouch:abc123)
    GOOGLE_APPLICATION_CREDENTIALS: Path to GCP service account JSON
"""

from __future__ import annotations

import os
from typing import Any

# Uncomment when using with actual ADK
# from google import genai

from vouch.integrations.adk import (
    VouchIntegrator,
    RiskPolicy,
    RiskLevel,
    protect_tools,
)


# =============================================================================
# Define Banking Tools
# =============================================================================


def get_account_balance(account_id: str, **kwargs) -> dict[str, Any]:
    """Get the current balance for an account.

    This is a LOW risk operation - read-only.

    Args:
        account_id: The account identifier

    Returns:
        Account balance information
    """
    # The vouch signature is injected by the integrator
    vouch_sig = kwargs.get("_vouch_signature", "none")
    print(f"  [get_account_balance] Vouch signature: {vouch_sig[:50]}...")

    # Simulated response
    return {
        "account_id": account_id,
        "balance": 10_000.00,
        "currency": "USD",
        "available": 9_500.00,
    }


def transfer_funds(
    from_account: str,
    to_account: str,
    amount: float,
    **kwargs,
) -> dict[str, Any]:
    """Transfer funds between accounts.

    This is a HIGH risk operation - will be flagged and require signing.

    Args:
        from_account: Source account ID
        to_account: Destination account ID
        amount: Amount to transfer

    Returns:
        Transfer confirmation
    """
    vouch_sig = kwargs.get("_vouch_signature", "none")
    risk_level = kwargs.get("_vouch_risk_level", "unknown")

    print(f"  [transfer_funds] Risk level: {risk_level}")
    print(f"  [transfer_funds] Vouch signature: {vouch_sig[:50]}...")

    # In production, you would send the vouch_sig to your banking API
    # as proof that this action was authorized by a verified agent

    return {
        "status": "completed",
        "from": from_account,
        "to": to_account,
        "amount": amount,
        "confirmation_id": "TXN-2024-001234",
        "vouch_verified": vouch_sig != "none",
    }


def delete_account(account_id: str, **kwargs) -> dict[str, Any]:
    """Delete an account permanently.

    This is a BLOCKED operation in our policy - should not be possible
    for the agent to execute without human approval.

    Args:
        account_id: Account to delete

    Returns:
        Should never return - operation is blocked
    """
    return {"error": "This should never execute"}


# =============================================================================
# Main Example
# =============================================================================


def main():
    """Demonstrate Vouch-protected banking agent."""
    print("=" * 60)
    print("Secure Banking Agent with Vouch Protocol")
    print("=" * 60)

    # Step 1: Configure Risk Policy
    policy = RiskPolicy(
        custom_rules={
            "delete_account": RiskLevel.BLOCKED,  # Never allow
        },
        cooldown_seconds=30.0,  # 30s cooldown between HIGH risk calls
    )

    # Step 2: Create VouchIntegrator
    integrator = VouchIntegrator(
        risk_policy=policy,
        enable_cloud_logging=False,  # Set True in production with GCP
        block_high_risk=False,  # Set True to require human approval
    )

    # Step 3: Protect the tools
    tools = [get_account_balance, transfer_funds, delete_account]
    protected_tools = integrator.protect(tools)

    # Get the protected versions
    protected_balance = protected_tools[0]
    protected_transfer = protected_tools[1]
    protected_delete = protected_tools[2]

    print("\n1. Testing LOW risk operation (get_account_balance):")
    print("-" * 40)
    try:
        result = protected_balance("ACC-12345")
        print(f"  Result: ${result['balance']:.2f} {result['currency']}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n2. Testing HIGH risk operation (transfer_funds):")
    print("-" * 40)
    try:
        result = protected_transfer(
            from_account="ACC-12345",
            to_account="ACC-67890",
            amount=500.00,
        )
        print(f"  Result: {result['status']} - {result['confirmation_id']}")
        print(f"  Vouch verified: {result['vouch_verified']}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n3. Testing BLOCKED operation (delete_account):")
    print("-" * 40)
    try:
        result = protected_delete("ACC-12345")
        print(f"  Result: {result}")  # Should never reach here
    except PermissionError as e:
        print(f"  ✅ Correctly blocked: {e}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n4. Testing HIGH risk cooldown:")
    print("-" * 40)
    try:
        print("  Attempting second transfer immediately...")
        result = protected_transfer(
            from_account="ACC-12345",
            to_account="ACC-99999",
            amount=100.00,
        )
        print(f"  Result: {result['status']}")  # May be blocked by cooldown
    except PermissionError as e:
        print(f"  ⏳ Cooldown active: {e}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)

    # Uncomment to use with actual Google ADK:
    #
    # client = genai.Client()
    #
    # agent = client.agents.create(
    #     model="gemini-2.0-flash",
    #     name="secure_banking_agent",
    #     tools=protected_tools,
    #     instruction="You are a secure banking assistant. Always verify transactions.",
    # )


if __name__ == "__main__":
    main()
