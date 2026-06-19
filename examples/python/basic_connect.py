#!/usr/bin/env python3
"""
Example: Connect to Vouch Daemon and Check Status

This is the simplest example - just connect and see if the daemon is running.
"""

from vouch_sdk import VouchClient, VouchConnectionError


def main():
    # Create a client (uses default localhost:21000)
    client = VouchClient()

    try:
        # Connect to the daemon
        status = client.connect()

        print("✅ Vouch Daemon is online!")
        print(f"   Version: {status.get('version', 'unknown')}")
        print(f"   Has Keys: {status.get('has_keys', False)}")
        print(f"   Uptime: {status.get('uptime', 0)} seconds")

    except VouchConnectionError as e:
        print("❌ Vouch Daemon is offline!")
        print(f"   Error: {e}")
        print("\n💡 Start the daemon with: vouch-bridge")
        return False

    return True


if __name__ == "__main__":
    main()
