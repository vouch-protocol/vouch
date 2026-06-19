# vouch/bridge/__init__.py
"""
Vouch Bridge Server - HTTP API for C2PA image signing and verification.

The bridge wraps Vouch Protocol's open-source media signing modules
(C2PA manifest embedding + QR badge overlay) as a FastAPI service.

Start the bridge:
    vouch-bridge
    # or
    uvicorn vouch.bridge.server:app --host 0.0.0.0 --port 21000
"""
