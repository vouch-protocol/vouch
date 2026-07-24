# Vouch Protocol Examples

This directory collects small examples for trying Vouch features and integrations.
Run commands below from the `examples/` directory unless the command says otherwise.

## Setup

```bash
pip install vouch-protocol
```

Some examples need optional packages such as `streamlit`, framework SDKs, or image/audio
libraries. Install those only for the example you want to run.

## Quick Start

| Example | Description | Run |
| --- | --- | --- |
| [01_hello_world.py](01_quickstart/01_hello_world.py) | Signs and verifies a first Vouch credential. | `python 01_quickstart/01_hello_world.py` |
| [02_key_generation.py](01_quickstart/02_key_generation.py) | Generates identities and stores keys. | `python 01_quickstart/02_key_generation.py` |
| [03_token_anatomy.py](01_quickstart/03_token_anatomy.py) | Shows the pieces inside a Vouch token. | `python 01_quickstart/03_token_anatomy.py` |

## Core Signing

| Example | Description | Run |
| --- | --- | --- |
| [01_sign_request.py](02_core/01_sign_request.py) | Signs outgoing HTTP-style requests. | `python 02_core/01_sign_request.py` |
| [01a_sign_credential.py](02_core/01a_sign_credential.py) | Signs a modern Vouch credential with Data Integrity proof. | `python 02_core/01a_sign_credential.py` |
| [02_verify_token.py](02_core/02_verify_token.py) | Verifies incoming Vouch tokens. | `python 02_core/02_verify_token.py` |
| [02a_verify_credential.py](02_core/02a_verify_credential.py) | Verifies a modern Vouch credential and detects tampering. | `python 02_core/02a_verify_credential.py` |
| [03_delegation_chain.py](02_core/03_delegation_chain.py) | Demonstrates agent-to-agent delegation. | `python 02_core/03_delegation_chain.py` |
| [04_audit_trail.py](02_core/04_audit_trail.py) | Issues credentials and records an audit trail. | `python 02_core/04_audit_trail.py` |

## Media And Audio

| Example | Description | Run |
| --- | --- | --- |
| [01_sign_image.py](03_media/01_sign_image.py) | Signs an image and writes a sidecar proof. | `python 03_media/01_sign_image.py 03_media/sample.jpg` |
| [02_verify_image.py](03_media/02_verify_image.py) | Verifies a signed image and detects tampering. | `python 03_media/02_verify_image.py 03_media/sample_signed.jpg` |
| [03_claim_types.py](03_media/03_claim_types.py) | Compares captured, signed, and shared media claims. | `python 03_media/03_claim_types.py` |
| [04_qr_badge.py](03_media/04_qr_badge.py) | Adds a QR verification badge to an image. | `python 03_media/04_qr_badge.py 03_media/sample.jpg` |
| [05_org_credentials.py](03_media/05_org_credentials.py) | Shows an organization-to-person media trust chain. | `python 03_media/05_org_credentials.py` |
| [sign_audio_demo.py](04_audio/sign_audio_demo.py) | Signs audio and demonstrates watermarking policy. | `python 04_audio/sign_audio_demo.py` |
| [c2pa_signing_example.py](c2pa/c2pa_signing_example.py) | Demonstrates C2PA-style media signing. | `python c2pa/c2pa_signing_example.py` |

Sample media files used by the image examples are in [03_media/](03_media/).

## Enterprise Features

| Example | Description | Run |
| --- | --- | --- |
| [01_reputation.py](04_enterprise/01_reputation.py) | Tracks behavior-based agent reputation. | `python 04_enterprise/01_reputation.py` |
| [02_key_rotation.py](04_enterprise/02_key_rotation.py) | Demonstrates key rotation. | `python 04_enterprise/02_key_rotation.py` |
| [03_revocation.py](04_enterprise/03_revocation.py) | Revokes keys and tokens. | `python 04_enterprise/03_revocation.py` |
| [04_rate_limiting.py](04_enterprise/04_rate_limiting.py) | Adds rate limiting around verification. | `python 04_enterprise/04_rate_limiting.py` |
| [05_caching.py](04_enterprise/05_caching.py) | Caches verification results. | `python 04_enterprise/05_caching.py` |

## Framework Integrations

| Example | Description | Run |
| --- | --- | --- |
| [01_langchain.py](05_integrations/01_langchain.py) | Uses Vouch with LangChain. | `python 05_integrations/01_langchain.py` |
| [02_crewai.py](05_integrations/02_crewai.py) | Uses Vouch with CrewAI. | `python 05_integrations/02_crewai.py` |
| [03_autogpt.py](05_integrations/03_autogpt.py) | Uses Vouch with AutoGPT. | `python 05_integrations/03_autogpt.py` |
| [03_crewai_agent.py](05_integrations/03_crewai_agent.py) | Runs a CrewAI-style agent example. | `python 05_integrations/03_crewai_agent.py` |
| [04_autogen.py](05_integrations/04_autogen.py) | Uses Vouch with Microsoft AutoGen. | `python 05_integrations/04_autogen.py` |
| [04_delegation.py](05_integrations/04_delegation.py) | Demonstrates delegated integration flow. | `python 05_integrations/04_delegation.py` |
| [05_n8n.py](05_integrations/05_n8n.py) | Shows a Vouch flow for n8n. | `python 05_integrations/05_n8n.py` |
| [06_streamlit.py](05_integrations/06_streamlit.py) | Runs a Streamlit integration demo. | `streamlit run 05_integrations/06_streamlit.py` |
| [07_mcp.py](05_integrations/07_mcp.py) | Uses Vouch with Model Context Protocol. | `python 05_integrations/07_mcp.py` |
| [08_vertex_ai.py](05_integrations/08_vertex_ai.py) | Uses Vouch with Google Vertex AI. | `python 05_integrations/08_vertex_ai.py` |
| [09_google_adk.py](05_integrations/09_google_adk.py) | Uses Vouch with Google ADK. | `python 05_integrations/09_google_adk.py` |
| [10_google_ai.py](05_integrations/10_google_ai.py) | Uses Vouch with Google AI SDK. | `python 05_integrations/10_google_ai.py` |
| [langchain_agent.py](langchain_agent.py) | Runs a LangChain agent demo. | `python langchain_agent.py` |
| [fastapi_server.py](fastapi_server.py) | Starts a FastAPI server with Vouch middleware. | `python fastapi_server.py` |
| [fastapi_credential_gate.py](fastapi_credential_gate.py) | Runs a FastAPI credential-gate example. | `python fastapi_credential_gate.py` |
| [hasura/demo_agent.py](hasura/demo_agent.py) | Runs the Hasura demo agent. | `python hasura/demo_agent.py` |

See also the integration-specific READMEs in [browser-extension/](browser-extension/),
[hasura/](hasura/), [mcp-vouch/](mcp-vouch/), [python/](python/), and
[typescript/](typescript/).

## Python SDK Examples

| Example | Description | Run |
| --- | --- | --- |
| [basic_connect.py](python/basic_connect.py) | Connects with the Python SDK. | `python python/basic_connect.py` |
| [basic_sign_text.py](python/basic_sign_text.py) | Signs text with the Python SDK. | `python python/basic_sign_text.py` |
| [async_client.py](python/async_client.py) | Uses the async Python client. | `python python/async_client.py` |
| [error_handling.py](python/error_handling.py) | Demonstrates client error handling. | `python python/error_handling.py` |
| [fastapi_integration.py](python/fastapi_integration.py) | Shows Python SDK use with FastAPI. | `python python/fastapi_integration.py` |
| [sign_file.py](python/sign_file.py) | Signs a local file. | `python python/sign_file.py` |
| [sign_image.py](python/sign_image.py) | Signs an image through the Python example flow. | `python python/sign_image.py` |
| [verify_media.py](python/verify_media.py) | Verifies signed media. | `python python/verify_media.py` |
| [cli_examples.sh](python/cli_examples.sh) | Runs CLI-oriented Python examples. | `bash python/cli_examples.sh` |

## TypeScript And Browser Examples

| Example | Description | Run |
| --- | --- | --- |
| [basic-connect.ts](typescript/basic-connect.ts) | Connects with the TypeScript SDK. | `npx tsx typescript/basic-connect.ts` |
| [basic-sign.ts](typescript/basic-sign.ts) | Signs data with the TypeScript SDK. | `npx tsx typescript/basic-sign.ts` |
| [sign-blob.ts](typescript/sign-blob.ts) | Signs a blob from TypeScript. | `npx tsx typescript/sign-blob.ts` |
| [error-handling.ts](typescript/error-handling.ts) | Demonstrates TypeScript client error handling. | `npx tsx typescript/error-handling.ts` |
| [react-component.tsx](typescript/react-component.tsx) | Shows a React component integration. | `npx tsx typescript/react-component.tsx` |
| [browser-basic.html](typescript/browser-basic.html) | Runs a browser-based example page. | `open typescript/browser-basic.html` |
| [background-usage.ts](browser-extension/background-usage.ts) | Shows browser-extension background usage. | `npx tsx browser-extension/background-usage.ts` |
| [secure-key-manager-usage.ts](browser-extension/secure-key-manager-usage.ts) | Shows browser-extension secure key storage usage. | `npx tsx browser-extension/secure-key-manager-usage.ts` |

## Standalone Demos

| Example | Description | Run |
| --- | --- | --- |
| [getting_started.py](getting_started.py) | Walks through a basic Vouch setup. | `python getting_started.py` |
| [accountability_demo.py](accountability_demo.py) | Demonstrates accountable agent actions. | `python accountability_demo.py` |
| [budget_payment_demo.py](budget_payment_demo.py) | Shows budget/payment-style policy checks. | `python budget_payment_demo.py` |
| [caveats_demo.py](caveats_demo.py) | Demonstrates caveat-constrained credentials. | `python caveats_demo.py` |
| [cross_device_identity.py](cross_device_identity.py) | Shows identity use across devices. | `python cross_device_identity.py` |
| [deliberation_demo.py](deliberation_demo.py) | Demonstrates reasoned deliberation evidence. | `python deliberation_demo.py` |
| [http_rendezvous_demo.py](http_rendezvous_demo.py) | Runs an HTTP rendezvous transport demo. | `python http_rendezvous_demo.py` |
| [hybrid_transport_demo.py](hybrid_transport_demo.py) | Demonstrates hybrid transport behavior. | `python hybrid_transport_demo.py` |
| [reasoned_action_demo.py](reasoned_action_demo.py) | Signs a reasoned action. | `python reasoned_action_demo.py` |
| [reputation_demo.py](reputation_demo.py) | Runs a standalone reputation example. | `python reputation_demo.py` |
| [mcp_trust_lifecycle.py](mcp_trust_lifecycle.py) | Walks one accountable agent task through the Vouch MCP lifecycle tools in order: delegate, check_action, check_trust, disclose_ai_origin, scan, reputation, attribute. | `python mcp_trust_lifecycle.py` |
| [robotics_demo.py](robotics_demo.py) | Demonstrates robotics identity and trust flow. | `python robotics_demo.py` |
| [disconnected_exchange_demo.py](disconnected_exchange_demo.py) | Two nodes authenticate and exchange authority fully offline over a simulated high-latency link, then apply the [bounded-staleness revocation](../docs/dtn-bounded-staleness-revocation.md) gate. | `python disconnected_exchange_demo.py` |
| [hardware_seam_demo.py](hardware_seam_demo.py) | A verifier decides whether to trust a peer for a maneuver using (simulated) sensors: freshness, channel-geometry presence, triangulated location, time-quality, kinematics, and integrity, all offline. | `python hardware_seam_demo.py` |
| [hardware_drivers/](hardware_drivers/) | Reference driver skeleton: copy and implement the `vouch.robotics.hardware` sensor Protocols for your platform. | `python hardware_drivers/drivers.py` |
| [secure_banking_agent.py](secure_banking_agent.py) | Runs a banking-style trusted agent demo. | `python secure_banking_agent.py` |
| [telephony_gateway.py](telephony_gateway.py) | Runs a voice/telephony gateway demo. | `python telephony_gateway.py` |
| [udna_rendezvous_demo.py](udna_rendezvous_demo.py) | Demonstrates uDNA rendezvous behavior. | `python udna_rendezvous_demo.py` |
| [who_wrote_this.py](who_wrote_this.py) | Shows authorship/provenance verification. | `python who_wrote_this.py` |
