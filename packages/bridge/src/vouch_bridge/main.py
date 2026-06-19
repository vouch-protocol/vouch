#!/usr/bin/env python3
"""
Vouch Bridge Entry Point

This module provides the entry point for the vouch-bridge console script.
"""

import uvicorn


def start():
    """Start the Vouch Bridge daemon on localhost:21000."""
    from vouch_bridge.server import app
    
    print("🚀 Starting Vouch Bridge Daemon...")
    print("📍 Listening on http://127.0.0.1:21000")
    print("🔐 Keys stored securely in system keyring")
    print("-" * 50)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=21000,
        log_level="info",
    )


if __name__ == "__main__":
    start()
