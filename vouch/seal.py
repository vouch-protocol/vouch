"""
Vouch Protocol Streamlit Seal Component.

This module has been moved to vouch.integrations.streamlit.seal

For backward compatibility, import from the new location:
    from vouch.integrations.streamlit import vouch_seal_component
"""

# Backward compatibility import
try:
    from vouch.integrations.streamlit.seal import vouch_seal_component, vouch_verification_card
except ImportError:

    def vouch_seal_component(*args, **kwargs):
        raise ImportError(
            "Streamlit integration requires streamlit. Install with: pip install streamlit"
        )

    def vouch_verification_card(*args, **kwargs):
        raise ImportError(
            "Streamlit integration requires streamlit. Install with: pip install streamlit"
        )


__all__ = ["vouch_seal_component", "vouch_verification_card"]
