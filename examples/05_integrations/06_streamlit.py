#!/usr/bin/env python3
"""
06_streamlit.py - Vouch with Streamlit

Build dashboards with signed AI actions.

Run: pip install streamlit && streamlit run 06_streamlit.py
"""

# If running as demo (not streamlit)
import sys

if "streamlit" not in sys.modules:
    print("📊 Streamlit + Vouch")
    print("=" * 50)
    print("Run with: streamlit run 06_streamlit.py")
    print()

from vouch import Signer, Verifier

# =============================================================================
# Streamlit App Code
# =============================================================================

STREAMLIT_CODE = """
import streamlit as st
from vouch import Signer, Verifier
from vouch.integrations.streamlit import VouchSession

# Initialize Vouch session
if "vouch" not in st.session_state:
    st.session_state.vouch = VouchSession(
        signer=Signer(name="Streamlit Agent")
    )

st.title("🔐 Vouch-Signed AI Dashboard")

# User input
user_query = st.text_input("Ask the AI:")

if st.button("Submit (Signed)"):
    # Sign the action
    token = st.session_state.vouch.sign_action({
        "action": "query",
        "input": user_query,
        "user": st.session_state.get("user_id", "anonymous")
    })
    
    # Show signature
    with st.expander("🔐 Vouch Signature"):
        st.code(token)
    
    # Process query (your AI logic)
    response = f"AI response to: {user_query}"
    
    # Sign the response too
    response_token = st.session_state.vouch.sign_action({
        "action": "response",
        "output": response
    })
    
    st.success(response)
    st.caption(f"Response signed: {response_token[:40]}...")

# Audit log
st.sidebar.header("📋 Signed Actions")
for action in st.session_state.vouch.get_audit_log():
    st.sidebar.text(action)
"""

print("📝 Streamlit App Code:")
print(STREAMLIT_CODE)

# =============================================================================
# Demo without Streamlit
# =============================================================================

print("\n" + "=" * 50)
print("📊 Demo (without Streamlit):")

signer = Signer(name="Streamlit Agent")

# Simulate user action
user_action = {"action": "query", "input": "What is the weather?"}
token = signer.sign(str(user_action))

print(f"   User action: {user_action}")
print(f"   Signed token: {token[:50]}...")

# Verify
verifier = Verifier()
result = verifier.verify(token)
print(f"   Verified: {result.valid}")

print("""
✅ Streamlit Benefits:
   • Dashboard actions are signed
   • AI responses are verifiable
   • Built-in audit log sidebar
   • Session-based identity
""")
