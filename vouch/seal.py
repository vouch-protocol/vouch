import streamlit as st

def vouch_seal_component(is_verified=False, agent_name="Agent"):
    if is_verified: 
        st.success(f"✅ {agent_name}: VOUCHED")
    else: 
        st.error(f"⚠️ {agent_name}: UNVERIFIED")
