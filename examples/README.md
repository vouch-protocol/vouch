# Vouch Protocol Examples

## 📚 Complete Example Library

These examples cover every feature and integration in Vouch Protocol.
Each example is self-contained and can be run directly.

---

## 🚀 Quick Start

| Example | Description | Run |
|---------|-------------|-----|
| [01_hello_world.py](01_quickstart/01_hello_world.py) | Your first credential (VC + `eddsa-jcs-2022`) | `python 01_quickstart/01_hello_world.py` |
| [02_key_generation.py](01_quickstart/02_key_generation.py) | Create and manage identities | `python 01_quickstart/02_key_generation.py` |
| [03_token_anatomy.py](01_quickstart/03_token_anatomy.py) | Anatomy of a legacy v0.x JWS token | `python 01_quickstart/03_token_anatomy.py` |

---

## 🔐 Core Signing

The modern path issues a Verifiable Credential with a Data Integrity
proof (`eddsa-jcs-2022`). The `01_`/`02_` examples use the legacy v0.x
JWS "Vouch-Token" path, retained during the deprecation window.

| Example | Description | Run |
|---------|-------------|-----|
| [01a_sign_credential.py](02_core/01a_sign_credential.py) | **Issue a credential (VC + Data Integrity)** | `python 02_core/01a_sign_credential.py` |
| [02a_verify_credential.py](02_core/02a_verify_credential.py) | **Verify a credential** | `python 02_core/02a_verify_credential.py` |
| [01_sign_request.py](02_core/01_sign_request.py) | Sign HTTP requests (legacy JWS) | `python 02_core/01_sign_request.py` |
| [02_verify_token.py](02_core/02_verify_token.py) | Verify incoming tokens (legacy JWS) | `python 02_core/02_verify_token.py` |
| [03_delegation_chain.py](02_core/03_delegation_chain.py) | Agent-to-agent delegation | `python 02_core/03_delegation_chain.py` |
| [04_audit_trail.py](02_core/04_audit_trail.py) | Create compliance audit trails | `python 02_core/04_audit_trail.py` |

---

## 📷 Media Signing

| Example | Description | Run |
|---------|-------------|-----|
| [01_sign_image.py](03_media/01_sign_image.py) | Sign images with Ed25519 | `python 03_media/01_sign_image.py` |
| [02_verify_image.py](03_media/02_verify_image.py) | Verify signed images | `python 03_media/02_verify_image.py` |
| [03_claim_types.py](03_media/03_claim_types.py) | CAPTURED vs SIGNED vs SHARED | `python 03_media/03_claim_types.py` |
| [04_qr_badge.py](03_media/04_qr_badge.py) | Add QR verification badges | `python 03_media/04_qr_badge.py` |
| [05_org_credentials.py](03_media/05_org_credentials.py) | Organization chain of trust | `python 03_media/05_org_credentials.py` |

---

## 🏢 Enterprise Features

| Example | Description | Run |
|---------|-------------|-----|
| [01_reputation.py](04_enterprise/01_reputation.py) | Agent trust scoring | `python 04_enterprise/01_reputation.py` |
| [02_key_rotation.py](04_enterprise/02_key_rotation.py) | Automatic key rotation | `python 04_enterprise/02_key_rotation.py` |
| [03_revocation.py](04_enterprise/03_revocation.py) | Key and token revocation | `python 04_enterprise/03_revocation.py` |
| [04_rate_limiting.py](04_enterprise/04_rate_limiting.py) | Protect APIs | `python 04_enterprise/04_rate_limiting.py` |
| [05_caching.py](04_enterprise/05_caching.py) | Verification caching | `python 04_enterprise/05_caching.py` |

---

## 🔌 Framework Integrations

| Example | Framework | Run |
|---------|-----------|-----|
| [01_langchain.py](05_integrations/01_langchain.py) | LangChain | `python 05_integrations/01_langchain.py` |
| [02_crewai.py](05_integrations/02_crewai.py) | CrewAI | `python 05_integrations/02_crewai.py` |
| [03_autogpt.py](05_integrations/03_autogpt.py) | AutoGPT | `python 05_integrations/03_autogpt.py` |
| [04_autogen.py](05_integrations/04_autogen.py) | Microsoft AutoGen | `python 05_integrations/04_autogen.py` |
| [05_n8n.py](05_integrations/05_n8n.py) | n8n Workflows | `python 05_integrations/05_n8n.py` |
| [06_streamlit.py](05_integrations/06_streamlit.py) | Streamlit | `streamlit run 05_integrations/06_streamlit.py` |
| [07_mcp.py](05_integrations/07_mcp.py) | Model Context Protocol | `python 05_integrations/07_mcp.py` |
| [08_vertex_ai.py](05_integrations/08_vertex_ai.py) | Google Vertex AI | `python 05_integrations/08_vertex_ai.py` |
| [09_google_adk.py](05_integrations/09_google_adk.py) | Google ADK | `python 05_integrations/09_google_adk.py` |
| [10_google_ai.py](05_integrations/10_google_ai.py) | Google AI SDK | `python 05_integrations/10_google_ai.py` |

---

## 🏗️ Real-World Applications

| Example | Description |
|---------|-------------|
| [secure_banking_agent.py](secure_banking_agent.py) | Banking AI with Vouch | 
| [telephony_gateway.py](telephony_gateway.py) | Voice AI gateway |
| [fastapi_server.py](fastapi_server.py) | FastAPI with Vouch middleware |
| [langchain_agent.py](langchain_agent.py) | LangChain agent |

---

## 📖 How to Use These Examples

1. **Install Vouch**:
   ```bash
   pip install vouch-protocol
   ```

2. **Run any example**:
   ```bash
   cd examples
   python 01_quickstart/01_hello_world.py
   ```

3. **Check the code**: Each example is heavily commented

---

## 📊 Coverage Matrix

| Category | Examples | Coverage |
|----------|----------|----------|
| Quick Start | 3 | ✅ Complete |
| Core Signing | 4 | ✅ Complete |
| Media Signing | 5 | ✅ Complete |
| Enterprise | 5 | ✅ Complete |
| Integrations | 10 | ✅ Complete |
| **Total** | **27** | ✅ Complete |
