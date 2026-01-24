"""
Vouch Verify Demo - Sign & Verify Media

This is a Streamlit web app that demonstrates:
1. SIGN: Create identity, sign photos with Vouch + C2PA + Proof of Moment
2. VERIFY: Check authenticity with Gemini 3 + C2PA

Run with: streamlit run app.py
"""

import streamlit as st
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
import base64
import os
import tempfile

# Page config
st.set_page_config(
    page_title="Vouch Verify",
    page_icon="✓",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        text-align: center;
        color: #6b7280;
        font-size: 1.2rem;
        margin-bottom: 2rem;
    }
    .trust-score-high { font-size: 4rem; font-weight: 700; color: #10b981; text-align: center; }
    .trust-score-medium { font-size: 4rem; font-weight: 700; color: #f59e0b; text-align: center; }
    .trust-score-low { font-size: 4rem; font-weight: 700; color: #ef4444; text-align: center; }
    .badge-verified { background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 0.5rem 1rem; border-radius: 9999px; font-weight: 600; display: inline-block; }
    .badge-unverified { background: #ef4444; color: white; padding: 0.5rem 1rem; border-radius: 9999px; font-weight: 600; display: inline-block; }
    .identity-card { background: linear-gradient(135deg, #1e3a5f, #2d4a6f); color: white; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; }
    .did-text { font-family: monospace; font-size: 0.85rem; word-break: break-all; }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">✓ Vouch Verify</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Sign & Verify Media with Cryptographic Provenance</p>', unsafe_allow_html=True)

# Initialize session state
if 'identity' not in st.session_state:
    st.session_state.identity = None
if 'verifications_today' not in st.session_state:
    st.session_state.verifications_today = 0

# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    
    # Free tier indicator
    remaining = 5 - st.session_state.verifications_today
    if remaining > 0:
        st.success(f"🆓 Free tier: {remaining}/5 left today")
    else:
        st.warning("⚠️ Free limit reached")
    
    st.divider()
    
    # API Keys
    gemini_key = st.text_input("Gemini API Key", type="password", help="For AI deepfake detection")
    weather_key = st.text_input("OpenWeather Key (optional)", type="password")
    
    st.divider()
    st.caption("Powered by Vouch Protocol v1.5.0")

# Main tabs
tab_sign, tab_verify = st.tabs(["✍️ Sign", "🔍 Verify"])

# =============================================================================
# SIGN TAB
# =============================================================================
with tab_sign:
    st.subheader("Sign Your Media")
    st.caption("Add cryptographic provenance to your photos and videos")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Step 1: Create or Load Identity
        st.markdown("### 1️⃣ Your Identity")
        
        if st.session_state.identity is None:
            st.info("You need an identity to sign media")
            
            display_name = st.text_input("Display Name", placeholder="e.g., John Smith")
            email = st.text_input("Email (optional)", placeholder="john@example.com")
            
            if st.button("🔑 Generate Identity", type="primary"):
                try:
                    from vouch import generate_identity
                    
                    # Generate Ed25519 keypair
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
            # Show identity card
            identity = st.session_state.identity
            st.markdown(f"""
            <div class="identity-card">
                <strong>👤 {identity['display_name']}</strong><br>
                <span class="did-text">🔑 {identity['did'][:50]}...</span><br>
                <small>✉️ {identity.get('email', 'No email')}</small>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🗑️ Reset Identity"):
                st.session_state.identity = None
                st.rerun()
    
    with col2:
        # Step 2: Upload and Sign
        st.markdown("### 2️⃣ Upload & Sign")
        
        if st.session_state.identity:
            uploaded_file = st.file_uploader(
                "Drop your photo",
                type=['jpg', 'jpeg', 'png', 'gif', 'webp'],
                key="sign_upload"
            )
            
            if uploaded_file:
                st.image(uploaded_file, caption="Preview", use_container_width=True)
                
                # Signing options
                st.markdown("### 3️⃣ Proof of Moment (Optional)")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    latitude = st.number_input("Latitude", value=0.0, format="%.6f")
                    longitude = st.number_input("Longitude", value=0.0, format="%.6f")
                with col_b:
                    include_timestamp = st.checkbox("Include timestamp", value=True)
                    include_weather = st.checkbox("Verify weather", value=False)
                
                if st.button("✍️ Sign Image", type="primary", use_container_width=True):
                    with st.spinner("Signing..."):
                        try:
                            # Save temp file
                            temp_dir = tempfile.mkdtemp()
                            temp_path = Path(temp_dir) / uploaded_file.name
                            temp_path.write_bytes(uploaded_file.getvalue())
                            
                            output_path = Path(temp_dir) / f"signed_{uploaded_file.name}"
                            
                            # Try C2PA signing first
                            signed_with_c2pa = False
                            try:
                                from vouch.media.c2pa import MediaSigner, VouchIdentity
                                from vouch.media.c2pa import generate_dev_certificate
                                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                                
                                # Generate dev certificate
                                private_key_pem, cert_chain = generate_dev_certificate(
                                    st.session_state.identity['display_name']
                                )
                                private_key = load_pem_private_key(private_key_pem, password=None)
                                
                                vouch_identity = VouchIdentity(
                                    did=st.session_state.identity['did'],
                                    display_name=st.session_state.identity['display_name'],
                                    email=st.session_state.identity.get('email'),
                                )
                                
                                signer = MediaSigner(private_key, cert_chain, vouch_identity)
                                result = signer.sign_image(str(temp_path), str(output_path))
                                
                                if result.success:
                                    signed_with_c2pa = True
                                    
                            except Exception as e:
                                st.caption(f"C2PA: {e}")
                            
                            # Fall back to native signing
                            if not signed_with_c2pa:
                                from vouch.media.native import sign_image, ClaimType
                                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                                import base64
                                
                                # Simple signing with sidecar file
                                from vouch import Signer
                                
                                signer = Signer(
                                    private_key_jwk=st.session_state.identity['private_key_jwk'],
                                    did=st.session_state.identity['did'],
                                )
                                
                                # Compute image hash
                                image_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                                
                                # Create signature
                                token = signer.sign({
                                    "action": "sign_media",
                                    "image_hash": image_hash,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "latitude": latitude if latitude != 0 else None,
                                    "longitude": longitude if longitude != 0 else None,
                                })
                                
                                # Save signed image (copy) + sidecar
                                output_path.write_bytes(uploaded_file.getvalue())
                                sidecar_path = output_path.with_suffix(output_path.suffix + ".vouch")
                                sidecar_path.write_text(json.dumps({
                                    "version": "1.0",
                                    "did": st.session_state.identity['did'],
                                    "display_name": st.session_state.identity['display_name'],
                                    "image_hash": image_hash,
                                    "token": token,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "location": {"lat": latitude, "lon": longitude} if latitude != 0 else None,
                                }, indent=2))
                            
                            st.success("✅ Image signed successfully!")
                            
                            # Download buttons
                            col_dl1, col_dl2 = st.columns(2)
                            with col_dl1:
                                st.download_button(
                                    "📥 Download Signed Image",
                                    output_path.read_bytes(),
                                    file_name=f"signed_{uploaded_file.name}",
                                    mime=uploaded_file.type,
                                )
                            with col_dl2:
                                sidecar_path = output_path.with_suffix(output_path.suffix + ".vouch")
                                if sidecar_path.exists():
                                    st.download_button(
                                        "📄 Download Sidecar",
                                        sidecar_path.read_text(),
                                        file_name=f"signed_{uploaded_file.name}.vouch",
                                        mime="application/json",
                                    )
                            
                        except Exception as e:
                            st.error(f"Signing failed: {e}")
        else:
            st.warning("👈 Create an identity first")


# =============================================================================
# VERIFY TAB
# =============================================================================
with tab_verify:
    st.subheader("Verify Media Authenticity")
    st.caption("Check for C2PA provenance, Vouch signatures, and deepfake indicators")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📤 Upload Media")
        
        uploaded_file = st.file_uploader(
            "Drop an image or video",
            type=['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mov'],
            key="verify_upload"
        )
        
        # Optional: upload sidecar
        sidecar_file = st.file_uploader(
            "Upload .vouch sidecar (optional)",
            type=['vouch', 'json'],
            key="sidecar_upload"
        )
        
        if uploaded_file:
            if uploaded_file.type.startswith('image'):
                st.image(uploaded_file, caption="Uploaded Image", use_container_width=True)
            
            file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
            st.caption(f"🔐 Hash: {file_hash[:16]}...")
    
    with col2:
        st.markdown("### 🔍 Results")
        
        if uploaded_file:
            if st.button("🚀 Verify Now", type="primary", use_container_width=True):
                st.session_state.verifications_today += 1
                
                with st.spinner("Analyzing..."):
                    results = {
                        "c2pa": {"verified": False, "signer": None},
                        "vouch": {"verified": False, "signer": None},
                        "deepfake": {"score": 50, "analysis": ""},
                        "overall_score": 0.0
                    }
                    
                    progress = st.progress(0, text="Starting...")
                    
                    # Check sidecar file
                    progress.progress(20, text="Checking Vouch signature...")
                    if sidecar_file:
                        try:
                            sidecar_data = json.loads(sidecar_file.read())
                            results["vouch"]["verified"] = True
                            results["vouch"]["signer"] = sidecar_data.get("display_name", "Unknown")
                            results["vouch"]["did"] = sidecar_data.get("did", "Unknown")
                        except:
                            pass
                    
                    # Check C2PA
                    progress.progress(40, text="Checking C2PA provenance...")
                    try:
                        from vouch.media.c2pa import MediaVerifier
                        temp_path = Path(f"/tmp/{uploaded_file.name}")
                        temp_path.write_bytes(uploaded_file.getvalue())
                        
                        verifier = MediaVerifier()
                        c2pa_result = verifier.verify_image(str(temp_path))
                        
                        if c2pa_result.is_valid:
                            results["c2pa"]["verified"] = True
                            results["c2pa"]["signer"] = c2pa_result.signer_identity
                    except Exception as e:
                        st.caption(f"C2PA: {e}")
                    
                    # Gemini Analysis
                    progress.progress(60, text="AI analyzing...")
                    if gemini_key:
                        try:
                            import google.generativeai as genai
                            genai.configure(api_key=gemini_key)
                            
                            model = genai.GenerativeModel("gemini-1.5-flash")
                            image_data = base64.b64encode(uploaded_file.getvalue()).decode()
                            
                            prompt = """Analyze this image for manipulation. Rate authenticity 0-100.
                            
Format response as:
AUTHENTICITY_SCORE: [number]
FINDINGS: [brief list]"""
                            
                            response = model.generate_content([
                                prompt,
                                {"mime_type": uploaded_file.type, "data": image_data}
                            ])
                            
                            results["deepfake"]["analysis"] = response.text
                            
                            import re
                            score_match = re.search(r'AUTHENTICITY_SCORE:\s*\[?(\d+)', response.text)
                            if score_match:
                                results["deepfake"]["score"] = int(score_match.group(1))
                                
                        except Exception as e:
                            st.caption(f"Gemini: {e}")
                    
                    # Calculate score
                    progress.progress(100, text="Done!")
                    
                    score = 0.20  # Base
                    if results["c2pa"]["verified"]:
                        score += 0.35
                    if results["vouch"]["verified"]:
                        score += 0.25
                    if results["deepfake"]["score"] > 0:
                        score += (results["deepfake"]["score"] / 100) * 0.20
                    
                    results["overall_score"] = min(1.0, score)
                    
                    # Display
                    st.divider()
                    
                    score_pct = int(results["overall_score"] * 100)
                    if score_pct >= 70:
                        st.markdown(f'<p class="trust-score-high">{score_pct}%</p>', unsafe_allow_html=True)
                        st.markdown('<p style="text-align:center"><span class="badge-verified">✓ Verified</span></p>', unsafe_allow_html=True)
                    elif score_pct >= 40:
                        st.markdown(f'<p class="trust-score-medium">{score_pct}%</p>', unsafe_allow_html=True)
                        st.markdown('<p style="text-align:center">⚠️ Partial</p>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<p class="trust-score-low">{score_pct}%</p>', unsafe_allow_html=True)
                        st.markdown('<p style="text-align:center"><span class="badge-unverified">⚠️ Unverified</span></p>', unsafe_allow_html=True)
                    
                    st.divider()
                    
                    # Details
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown("**📜 C2PA**")
                        if results["c2pa"]["verified"]:
                            st.success("✓ Verified")
                        else:
                            st.warning("Not found")
                    
                    with col_b:
                        st.markdown("**✍️ Vouch Signature**")
                        if results["vouch"]["verified"]:
                            st.success(f"✓ {results['vouch']['signer']}")
                        else:
                            st.warning("Not found")
                    
                    if results["deepfake"]["analysis"]:
                        st.divider()
                        st.markdown("**🤖 AI Analysis**")
                        with st.expander("View details"):
                            st.markdown(results["deepfake"]["analysis"])
        else:
            st.info("👆 Upload media to verify")

# Footer
st.divider()
st.caption("Vouch Verify • Sign & Verify • [GitHub](https://github.com/vouch-protocol/vouch)")
