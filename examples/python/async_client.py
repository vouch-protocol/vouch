#!/usr/bin/env python3
"""
Example: Async Client Usage

The AsyncVouchClient is designed for async frameworks like:
- FastAPI
- aiohttp
- Starlette
- Quart

It provides the same API as VouchClient but with async/await.
"""

import asyncio
from vouch_sdk import AsyncVouchClient, VouchConnectionError


async def basic_async_usage():
    """Basic async connection and signing."""
    client = AsyncVouchClient()

    # Connect (async)
    status = await client.connect()
    print(f"✅ Daemon status: {status['status']}")

    # Sign (async)
    result = await client.sign("Async content", origin="async-example")
    print(f"✅ Signature: {result['signature'][:32]}...")


async def sign_multiple_concurrently():
    """Sign multiple items at the same time for maximum speed."""
    client = AsyncVouchClient()

    # Items to sign
    items = [
        "Document 1: Contract draft",
        "Document 2: Invoice #12345",
        "Document 3: Meeting notes",
        "Document 4: Code review",
        "Document 5: Deployment plan",
    ]

    # Sign all concurrently
    tasks = [
        client.sign(item, origin="batch-async", document_id=f"doc-{i}")
        for i, item in enumerate(items)
    ]

    results = await asyncio.gather(*tasks)

    for i, result in enumerate(results):
        print(f"✅ Document {i + 1}: {result['signature'][:16]}...")

    print(f"\n📊 Signed {len(results)} documents concurrently!")


async def async_file_signing():
    """Sign files asynchronously."""
    from pathlib import Path

    client = AsyncVouchClient()

    # Create test file
    test_file = Path("async_test.txt")
    test_file.write_text("Content for async file signing test")

    try:
        signed_bytes = await client.sign_file(str(test_file), origin="async-file-signer")

        output = Path("async_test_signed.txt")
        output.write_bytes(signed_bytes)

        print(f"✅ Async file signed: {output}")

    finally:
        # Cleanup
        test_file.unlink(missing_ok=True)


async def async_with_timeout():
    """Handle timeouts gracefully."""
    # Create client with custom timeout
    client = AsyncVouchClient(timeout=5.0)  # 5 second timeout

    try:
        await asyncio.wait_for(client.sign("Quick content", origin="timeout-example"), timeout=10.0)
        print("✅ Completed within timeout")

    except asyncio.TimeoutError:
        print("⚠️ Request timed out")


async def async_error_handling():
    """Proper error handling in async context."""
    from vouch_sdk import NoKeysConfiguredError, UserDeniedSignatureError

    client = AsyncVouchClient()

    try:
        await client.sign("Content", origin="error-handling-demo")

    except VouchConnectionError:
        print("❌ Daemon offline - cannot proceed")
        # Maybe queue for later?

    except NoKeysConfiguredError:
        print("❌ No keys - user needs to set up identity")
        # Show setup instructions

    except UserDeniedSignatureError:
        print("⚠️ User declined - respecting their choice")
        # Log for audit, don't retry


async def main():
    try:
        print("\n🔄 Example 1: Basic async usage")
        await basic_async_usage()

        print("\n🔄 Example 2: Concurrent signing")
        await sign_multiple_concurrently()

        print("\n🔄 Example 3: Async file signing")
        await async_file_signing()

        print("\n🔄 Example 4: Error handling")
        await async_error_handling()

    except VouchConnectionError:
        print("❌ Daemon not running. Start with: vouch-bridge")


if __name__ == "__main__":
    asyncio.run(main())
