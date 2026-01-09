#!/usr/bin/env python3
"""
02_crewai.py - Vouch with CrewAI

Sign actions in multi-agent CrewAI teams.

Run: pip install crewai && python 02_crewai.py
"""

from vouch import Signer

print("👥 CrewAI + Vouch")
print("=" * 50)

# Each crew member gets their own identity
researcher = Signer(name="Researcher Agent")
writer = Signer(name="Writer Agent")
reviewer = Signer(name="Reviewer Agent")

print(f"🔬 Researcher: {researcher.public_key[:20]}...")
print(f"✍️  Writer: {writer.public_key[:20]}...")
print(f"📋 Reviewer: {reviewer.public_key[:20]}...")

# =============================================================================
# CrewAI Integration
# =============================================================================

print("\n📦 CrewAI Integration")
print("=" * 50)

print("""
from crewai import Agent, Task, Crew
from vouch.integrations.crewai import VouchCrewAI

# Create agents with Vouch identities
researcher = Agent(
    role="Researcher",
    goal="Find information",
    vouch_signer=Signer(name="Researcher"),
)

writer = Agent(
    role="Writer", 
    goal="Write content",
    vouch_signer=Signer(name="Writer"),
)

# Create crew
crew = Crew(
    agents=[researcher, writer],
    tasks=[...],
)

# Every action in the crew is signed!
result = crew.kickoff()
""")

# =============================================================================
# What Gets Signed
# =============================================================================

print("\n📝 What Gets Signed:")
print("  ✅ Tool calls from each agent")
print("  ✅ Inter-agent messages")
print("  ✅ Task completions")
print("  ✅ Final crew output")

print("\n👥 Multi-Agent Accountability:")
print("  • Each agent has unique identity")
print("  • Actions are attributable")
print("  • Audit trail across entire crew")
