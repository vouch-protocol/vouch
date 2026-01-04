"""
Vouch Protocol Streamlit Integration.

Provides UI components for displaying verification status in Streamlit apps.
"""

from typing import Optional

try:
    import streamlit as st

    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False
    st = None


def vouch_seal_component(
    is_verified: bool = False,
    agent_name: str = "Agent",
    agent_did: Optional[str] = None,
    show_details: bool = False,
) -> None:
    """
    Display a Vouch verification seal in a Streamlit app.

    Args:
        is_verified: Whether the agent is verified.
        agent_name: Display name of the agent.
        agent_did: Optional DID to display.
        show_details: Whether to show additional details.

    Raises:
        ImportError: If streamlit is not installed.

    Example:
        >>> import streamlit as st
        >>> from vouch.integrations.streamlit import vouch_seal_component
        >>> vouch_seal_component(is_verified=True, agent_name="Finance Bot")
    """
    if not STREAMLIT_AVAILABLE:
        raise ImportError("Streamlit is not installed. Install with: pip install streamlit")

    if is_verified:
        st.success(f"✅ {agent_name}: VOUCHED")
        if show_details and agent_did:
            st.caption(f"DID: {agent_did}")
    else:
        st.error(f"⚠️ {agent_name}: UNVERIFIED")
        if show_details:
            st.caption("This agent has not provided valid identity credentials.")


def vouch_verification_card(
    agent_name: str,
    agent_did: str,
    is_verified: bool,
    reputation_score: Optional[int] = None,
    payload: Optional[dict] = None,
) -> None:
    """
    Display a detailed verification card for an agent.

    Args:
        agent_name: Display name of the agent.
        agent_did: The agent's DID.
        is_verified: Whether verification succeeded.
        reputation_score: Optional reputation score (0-100).
        payload: Optional signed payload to display.
    """
    if not STREAMLIT_AVAILABLE:
        raise ImportError("Streamlit is not installed")

    with st.container():
        col1, col2 = st.columns([1, 4])

        with col1:
            if is_verified:
                st.markdown("### ✅")
            else:
                st.markdown("### ⚠️")

        with col2:
            st.markdown(f"**{agent_name}**")
            st.caption(agent_did)

            if is_verified and reputation_score is not None:
                st.progress(reputation_score / 100)
                st.caption(f"Reputation: {reputation_score}/100")

            if payload:
                with st.expander("Signed Payload"):
                    st.json(payload)
