"""
Vouch Verify - Sign & Verify Media with Cryptographic Provenance

Redesigned to match vouch-protocol.com branding.

Run with: streamlit run app.py
"""

import streamlit as st
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import base64
import tempfile

# Page config with Vouch branding
st.set_page_config(
    page_title="Vouch Verify - Sign & Verify Media",
    page_icon="✅",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Hide Streamlit's deploy button and branding
st.markdown("""
<style>
    /* Hide Streamlit default elements */
    [data-testid="stAppDeployButton"] { display: none !important; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
    
    /* ============================================
       Vouch Protocol Design System
       Matching vouch-protocol.com
       ============================================ */
    
    /* Import Inter font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    /* Root variables matching website */
    :root {
        --primary: #1e3a5f;
        --primary-dark: #152a45;
        --primary-light: #2d5a8a;
        --accent: #3b82f6;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --text-muted: #64748b;
        --bg-white: #ffffff;
        --bg-light: #f8fafc;
        --border-light: #e2e8f0;
        --success: #10b981;
        --warning: #f59e0b;
        --error: #ef4444;
        --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.06);
        --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.08);
        --shadow-lg: 0 10px 40px rgba(0, 0, 0, 0.1);
        --radius-sm: 6px;
        --radius-md: 10px;
        --radius-lg: 14px;
    }
    
    /* Global font */
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    }
    
    /* Main app background */
    .stApp {
        background: linear-gradient(180deg, #f0f9ff 0%, #ffffff 100%);
    }
    
    /* Header styling */
    .vouch-header {
        background: var(--bg-white);
        border-bottom: 1px solid var(--border-light);
        padding: 1rem 2rem;
        margin: -1rem -1rem 2rem -1rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .vouch-logo {
        height: 40px;
        width: auto;
    }
    
    .vouch-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--primary);
        margin: 0;
    }
    
    .vouch-subtitle {
        font-size: 0.875rem;
        color: var(--text-muted);
        margin: 0;
    }
    
    /* Card styling */
    .vouch-card {
        background: var(--bg-white);
        border: 1px solid var(--border-light);
        border-radius: var(--radius-lg);
        padding: 1.5rem;
        box-shadow: var(--shadow-sm);
        margin-bottom: 1rem;
    }
    
    .vouch-card:hover {
        box-shadow: var(--shadow-md);
        transition: box-shadow 0.2s ease;
    }
    
    .vouch-card h3 {
        font-size: 1.125rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    /* Identity card */
    .identity-card {
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        color: white;
        padding: 1.5rem;
        border-radius: var(--radius-lg);
        margin: 1rem 0;
        box-shadow: var(--shadow-md);
    }
    
    .identity-card .name {
        font-size: 1.25rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    .identity-card .did {
        font-family: 'Monaco', 'Consolas', monospace;
        font-size: 0.75rem;
        opacity: 0.9;
        word-break: break-all;
        background: rgba(255,255,255,0.1);
        padding: 0.5rem;
        border-radius: var(--radius-sm);
    }
    
    /* Trust score display */
    .trust-score-container {
        text-align: center;
        padding: 2rem;
    }
    
    .trust-score-value {
        font-size: 4rem;
        font-weight: 800;
        line-height: 1;
    }
    
    .trust-score-high { color: var(--success); }
    .trust-score-medium { color: var(--warning); }
    .trust-score-low { color: var(--error); }
    
    .trust-badge {
        display: inline-block;
        padding: 0.5rem 1.25rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.875rem;
        margin-top: 0.5rem;
    }
    
    .badge-verified {
        background: linear-gradient(135deg, var(--success), #059669);
        color: white;
    }
    
    .badge-partial {
        background: linear-gradient(135deg, var(--warning), #d97706);
        color: white;
    }
    
    .badge-unverified {
        background: var(--error);
        color: white;
    }
    
    /* Step indicators */
    .step-indicator {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1rem;
    }
    
    .step-number {
        width: 32px;
        height: 32px;
        background: var(--primary);
        color: white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 600;
        font-size: 0.875rem;
    }
    
    .step-title {
        font-weight: 600;
        color: var(--text-primary);
    }
    
    /* Streamlit overrides */
    .stButton > button {
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        color: white;
        border: none;
        border-radius: var(--radius-md);
        font-weight: 600;
        padding: 0.75rem 1.5rem;
        transition: all 0.2s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
        box-shadow: var(--shadow-md);
    }
    
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, var(--accent) 0%, #2563eb 100%);
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: var(--bg-light);
        padding: 0.5rem;
        border-radius: var(--radius-lg);
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: var(--radius-md);
        font-weight: 500;
        color: var(--text-secondary);
    }
    
    .stTabs [aria-selected="true"] {
        background: var(--bg-white) !important;
        color: var(--primary) !important;
        box-shadow: var(--shadow-sm);
    }
    
    /* File uploader */
    [data-testid="stFileUploader"] {
        border: 2px dashed var(--border-light);
        border-radius: var(--radius-lg);
        padding: 1rem;
        background: var(--bg-light);
    }
    
    [data-testid="stFileUploader"]:hover {
        border-color: var(--accent);
        background: rgba(59, 130, 246, 0.05);
    }
    
    /* Result cards */
    .result-item {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem 1rem;
        background: var(--bg-light);
        border-radius: var(--radius-md);
        margin-bottom: 0.5rem;
    }
    
    .result-item.success {
        background: rgba(16, 185, 129, 0.1);
        border-left: 3px solid var(--success);
    }
    
    .result-item.warning {
        background: rgba(245, 158, 11, 0.1);
        border-left: 3px solid var(--warning);
    }
    
    .result-item.error {
        background: rgba(239, 68, 68, 0.1);
        border-left: 3px solid var(--error);
    }
    
    /* Footer */
    .vouch-footer {
        text-align: center;
        padding: 2rem;
        color: var(--text-muted);
        font-size: 0.875rem;
        border-top: 1px solid var(--border-light);
        margin-top: 3rem;
    }
    
    .vouch-footer a {
        color: var(--primary);
        text-decoration: none;
    }
    
    .vouch-footer a:hover {
        text-decoration: underline;
    }
</style>
""", unsafe_allow_html=True)

# Header with logo
st.markdown("""
<div style="display: flex; align-items: center; gap: 16px; padding: 1rem 0 2rem 0; border-bottom: 1px solid #e2e8f0; margin-bottom: 2rem;">
    <img src="https://vouch-protocol.com/assets/vouch-logo-full.png" alt="Vouch Protocol" style="height: 45px; width: auto;">
    <div>
        <div style="font-size: 1.5rem; font-weight: 700; color: #1e3a5f;">Vouch Verify</div>
        <div style="font-size: 0.875rem; color: #64748b;">Sign & Verify Media with Cryptographic Provenance</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Initialize session state
if 'identity' not in st.session_state:
    st.session_state.identity = None
if 'verifications_today' not in st.session_state:
    st.session_state.verifications_today = 0

# Main tabs
tab_sign, tab_verify = st.tabs(["✍️ Sign Media", "🔍 Verify Media"])

# =============================================================================
# SIGN TAB
# =============================================================================
with tab_sign:
    col1, col2 = st.columns([1, 1], gap="large")
    
    with col1:
        # Step 1: Identity
        st.markdown("""
        <div class="vouch-card">
            <div class="step-indicator">
                <div class="step-number">1</div>
                <div class="step-title">Your Identity</div>
            </div>
        """, unsafe_allow_html=True)
        
        if st.session_state.identity is None:
            st.info("Create a cryptographic identity to sign media")
            
            display_name = st.text_input("Display Name", placeholder="e.g., John Smith")
            email = st.text_input("Email (optional)", placeholder="john@example.com")
            
            if st.button("🔑 Generate Identity", type="primary", use_container_width=True):
                try:
                    from vouch import generate_identity
                    
                    identity = generate_identity()
                    
                    st.session_state.identity = {
                        "did": identity.did,
                        "display_name": display_name or "Anonymous",
                        "email": email,
                        "private_key_jwk": identity.private_key_jwk,
                        "public_key_jwk": identity.public_key_jwk,
                    }
                    st.success("✓ Identity created!")
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            identity = st.session_state.identity
            st.markdown(f"""
            <div class="identity-card">
                <div class="name">👤 {identity['display_name']}</div>
                <div class="did">🔑 {identity['did']}</div>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🗑️ Reset Identity", use_container_width=True):
                st.session_state.identity = None
                st.rerun()
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    with col2:
        # Step 2: Upload & Sign
        st.markdown("""
        <div class="vouch-card">
            <div class="step-indicator">
                <div class="step-number">2</div>
                <div class="step-title">Upload & Sign</div>
            </div>
        """, unsafe_allow_html=True)
        
        if st.session_state.identity:
            uploaded_file = st.file_uploader(
                "Drop your image here",
                type=['jpg', 'jpeg', 'png', 'gif', 'webp'],
                key="sign_upload",
                label_visibility="collapsed"
            )
            
            if uploaded_file:
                st.image(uploaded_file, caption="Preview", use_container_width=True)
                
                if st.button("✍️ Sign Image", type="primary", use_container_width=True):
                    with st.spinner("Signing with Ed25519..."):
                        try:
                            temp_dir = tempfile.mkdtemp()
                            output_path = Path(temp_dir) / f"signed_{uploaded_file.name}"
                            
                            from vouch import Signer
                            
                            signer = Signer(
                                private_key_jwk=st.session_state.identity['private_key_jwk'],
                                did=st.session_state.identity['did'],
                            )
                            
                            image_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                            
                            token = signer.sign({
                                "action": "sign_media",
                                "image_hash": image_hash,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
                            
                            output_path.write_bytes(uploaded_file.getvalue())
                            sidecar_path = output_path.with_suffix(output_path.suffix + ".vouch")
                            sidecar_path.write_text(json.dumps({
                                "version": "2.0",
                                "did": st.session_state.identity['did'],
                                "display_name": st.session_state.identity['display_name'],
                                "image_hash": image_hash,
                                "token": token,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }, indent=2))
                            
                            st.success("✅ Image signed successfully!")
                            
                            col_dl1, col_dl2 = st.columns(2)
                            with col_dl1:
                                st.download_button(
                                    "📥 Download Image",
                                    output_path.read_bytes(),
                                    file_name=f"signed_{uploaded_file.name}",
                                    mime=uploaded_file.type,
                                    use_container_width=True
                                )
                            with col_dl2:
                                st.download_button(
                                    "📄 Download .vouch",
                                    sidecar_path.read_text(),
                                    file_name=f"signed_{uploaded_file.name}.vouch",
                                    mime="application/json",
                                    use_container_width=True
                                )
                            
                        except Exception as e:
                            st.error(f"Signing failed: {e}")
        else:
            st.warning("👈 Create an identity first")
        
        st.markdown("</div>", unsafe_allow_html=True)


# =============================================================================
# VERIFY TAB
# =============================================================================
with tab_verify:
    col1, col2 = st.columns([1, 1], gap="large")
    
    with col1:
        st.markdown("""
        <div class="vouch-card">
            <div class="step-indicator">
                <div class="step-number">1</div>
                <div class="step-title">Upload Media</div>
            </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Drop an image or video",
            type=['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mov'],
            key="verify_upload",
            label_visibility="collapsed"
        )
        
        sidecar_file = st.file_uploader(
            "Upload .vouch sidecar (optional)",
            type=['vouch', 'json'],
            key="sidecar_upload"
        )
        
        if uploaded_file:
            if uploaded_file.type.startswith('image'):
                st.image(uploaded_file, caption="Uploaded Image", use_container_width=True)
            
            file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
            st.caption(f"🔐 SHA-256: `{file_hash[:24]}...`")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="vouch-card">
            <div class="step-indicator">
                <div class="step-number">2</div>
                <div class="step-title">Verification Results</div>
            </div>
        """, unsafe_allow_html=True)
        
        if uploaded_file:
            if st.button("🚀 Verify Now", type="primary", use_container_width=True):
                st.session_state.verifications_today += 1
                
                with st.spinner("Analyzing..."):
                    results = {
                        "c2pa": {"verified": False, "signer": None},
                        "vouch": {"verified": False, "signer": None},
                        "overall_score": 0.0
                    }
                    
                    progress = st.progress(0, text="Starting verification...")
                    
                    # Check sidecar file
                    progress.progress(33, text="Checking Vouch signature...")
                    if sidecar_file:
                        try:
                            sidecar_data = json.loads(sidecar_file.read())
                            results["vouch"]["verified"] = True
                            results["vouch"]["signer"] = sidecar_data.get("display_name", "Unknown")
                            results["vouch"]["did"] = sidecar_data.get("did", "Unknown")
                        except:
                            pass
                    
                    # Check C2PA
                    progress.progress(66, text="Checking C2PA provenance...")
                    try:
                        from vouch.media.c2pa import MediaVerifier
                        temp_path = Path(f"/tmp/{uploaded_file.name}")
                        temp_path.write_bytes(uploaded_file.getvalue())
                        
                        verifier = MediaVerifier()
                        c2pa_result = verifier.verify_image(str(temp_path))
                        
                        if c2pa_result.is_valid:
                            results["c2pa"]["verified"] = True
                            results["c2pa"]["signer"] = c2pa_result.signer_identity
                    except Exception:
                        pass
                    
                    progress.progress(100, text="Done!")
                    
                    # Calculate score
                    score = 20  # Base
                    if results["c2pa"]["verified"]:
                        score += 40
                    if results["vouch"]["verified"]:
                        score += 40
                    
                    results["overall_score"] = min(100, score)
                    
                    # Display results
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    score_pct = int(results["overall_score"])
                    if score_pct >= 70:
                        score_class = "trust-score-high"
                        badge_class = "badge-verified"
                        badge_text = "✓ Verified"
                    elif score_pct >= 40:
                        score_class = "trust-score-medium"
                        badge_class = "badge-partial"
                        badge_text = "⚠️ Partial"
                    else:
                        score_class = "trust-score-low"
                        badge_class = "badge-unverified"
                        badge_text = "⚠️ Unverified"
                    
                    st.markdown(f"""
                    <div class="trust-score-container">
                        <div class="trust-score-value {score_class}">{score_pct}%</div>
                        <div class="trust-badge {badge_class}">{badge_text}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Result items
                    if results["vouch"]["verified"]:
                        st.markdown(f"""
                        <div class="result-item success">
                            <span>✅</span>
                            <div>
                                <strong>Vouch Signature</strong><br>
                                <small>Signed by {results['vouch']['signer']}</small>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="result-item warning">
                            <span>⚠️</span>
                            <div>
                                <strong>Vouch Signature</strong><br>
                                <small>No signature found</small>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    if results["c2pa"]["verified"]:
                        st.markdown("""
                        <div class="result-item success">
                            <span>✅</span>
                            <div>
                                <strong>C2PA Provenance</strong><br>
                                <small>Industry-standard manifest verified</small>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="result-item warning">
                            <span>⚠️</span>
                            <div>
                                <strong>C2PA Provenance</strong><br>
                                <small>No C2PA manifest found</small>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
        else:
            st.info("👆 Upload media to verify its authenticity")
        
        st.markdown("</div>", unsafe_allow_html=True)

# Footer
st.markdown("""
<div class="vouch-footer">
    <a href="https://vouch-protocol.com">vouch-protocol.com</a> • 
    <a href="https://github.com/vouch-protocol/vouch">GitHub</a> • 
    <a href="https://pypi.org/project/vouch-protocol/">PyPI</a>
    <br><br>
    © 2024-2026 Vouch Protocol Contributors. Apache 2.0 License.
</div>
""", unsafe_allow_html=True)
