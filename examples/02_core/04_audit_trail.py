#!/usr/bin/env python3
"""
04_audit_trail.py - Create Audit Trails

Log all agent actions for compliance.

Run: python 04_audit_trail.py
"""

from vouch import Signer, Auditor
import json

print("📋 Audit Trail")
print("=" * 50)

# =============================================================================
# Setup Auditor
# =============================================================================

# Create auditor (stores audit events)
auditor = Auditor()

# Create an agent
agent = Signer(name="Financial Agent", email="fin@example.com")

print(f"Agent: {agent.name}")
print("Auditor ready\n")

# =============================================================================
# Log Actions
# =============================================================================

print("📝 Logging Actions:")

# Action 1: Query balance
action1 = {"action": "get_balance", "account": "12345"}
token1 = agent.sign(json.dumps(action1))
auditor.log(token=token1, metadata={"ip": "10.0.0.1", "department": "treasury"})
print("   ✅ get_balance logged")

# Action 2: Transfer funds
action2 = {"action": "transfer", "from": "12345", "to": "67890", "amount": 500}
token2 = agent.sign(json.dumps(action2))
auditor.log(token=token2, metadata={"ip": "10.0.0.1", "approved_by": "manager@example.com"})
print("   ✅ transfer logged")

# Action 3: Generate report
action3 = {"action": "generate_report", "type": "monthly_summary"}
token3 = agent.sign(json.dumps(action3))
auditor.log(token=token3, metadata={"ip": "10.0.0.1"})
print("   ✅ generate_report logged")

# =============================================================================
# Query Audit Log
# =============================================================================

print("\n📊 Query Audit Log:")

# Get all events
print("\n   All events:")
for event in auditor.query(limit=10):
    payload = json.loads(event.payload)
    print(f"   - {payload['action']} at {event.timestamp}")

# Filter by agent
print(f"\n   Events for {agent.name}:")
for event in auditor.query(agent_id=agent.public_key, limit=10):
    payload = json.loads(event.payload)
    print(f"   - {payload['action']}")

# Filter by action type
print("\n   Transfer operations only:")
for event in auditor.query(limit=10):
    payload = json.loads(event.payload)
    if payload.get('action') == 'transfer':
        print(f"   - Transfer ${payload['amount']} from {payload['from']} to {payload['to']}")

# =============================================================================
# Export for Compliance
# =============================================================================

print("\n📤 Export for Compliance:")

# Export as JSON
events = auditor.export(format="json")
print(f"   Exported {len(events)} events as JSON")

# Export as CSV (for spreadsheets)
# csv_data = auditor.export(format="csv")
# print(f"   Exported as CSV")

# =============================================================================
# Summary
# =============================================================================

print("""
📝 AUDIT TRAIL FEATURES:

What's Logged:
  • Full signed token (unforgeable)
  • Timestamp
  • Agent identity
  • Custom metadata (IP, user, etc.)

Query Options:
  • By agent (public key)
  • By time range
  • By action type
  • Full-text search

Export Formats:
  • JSON (for APIs)
  • CSV (for compliance reports)
  • Custom (implement your own)

Compliance:
  • SOC2 audit trail
  • GDPR action logging
  • Financial regulations
""")
