#!/usr/bin/env python3
"""
Example: Comprehensive Error Handling

Demonstrates how to gracefully handle all possible error conditions
when using the Vouch SDK.
"""

from vouch_sdk import (
    VouchClient,
    AsyncVouchClient,
    VouchError,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
)


def basic_error_handling():
    """
    Basic pattern: catch specific exceptions.
    """
    client = VouchClient()
    
    try:
        result = client.sign("Content to sign", origin="error-demo")
        print(f"✅ Signed: {result['signature'][:32]}...")
        
    except VouchConnectionError as e:
        # Daemon is not running or unreachable
        print(f"❌ Connection Error: {e}")
        print("   → Start the daemon: vouch-bridge")
        
    except NoKeysConfiguredError as e:
        # Daemon is running but no identity has been set up
        print(f"❌ No Keys Configured: {e}")
        print("   → Generate keys via the daemon")
        
    except UserDeniedSignatureError as e:
        # User clicked "Deny" in the consent popup
        print(f"⚠️ User Denied Signature: {e}")
        print("   → User chose not to sign this content")


def hierarchical_error_handling():
    """
    Catch base VouchError to handle all SDK errors uniformly.
    """
    client = VouchClient()
    
    try:
        result = client.sign("Content", origin="hierarchical-demo")
        return result
        
    except VouchError as e:
        # Catches ALL Vouch SDK errors
        print(f"Vouch operation failed: {type(e).__name__}: {e}")
        return None


def retry_pattern():
    """
    Retry pattern for transient failures.
    """
    import time
    
    client = VouchClient()
    
    max_retries = 3
    retry_delay = 2  # seconds
    
    for attempt in range(1, max_retries + 1):
        try:
            result = client.sign("Important content", origin="retry-demo")
            print(f"✅ Succeeded on attempt {attempt}")
            return result
            
        except VouchConnectionError:
            if attempt < max_retries:
                print(f"⚠️ Attempt {attempt} failed, retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                print(f"❌ All {max_retries} attempts failed")
                raise
                
        except (NoKeysConfiguredError, UserDeniedSignatureError):
            # Don't retry these - they require user action
            raise


def fallback_pattern():
    """
    Fallback to alternative behavior when signing fails.
    """
    client = VouchClient()
    
    content = "Content that should be signed"
    
    try:
        result = client.sign(content, origin="fallback-demo")
        return {
            "content": content,
            "signature": result["signature"],
            "signed": True,
        }
        
    except VouchConnectionError:
        # Fallback: proceed without signature
        print("⚠️ Daemon offline - proceeding without signature")
        return {
            "content": content,
            "signature": None,
            "signed": False,
            "reason": "daemon_offline",
        }
        
    except NoKeysConfiguredError:
        print("⚠️ No identity - proceeding as anonymous")
        return {
            "content": content,
            "signature": None,
            "signed": False,
            "reason": "no_identity",
        }
        
    except UserDeniedSignatureError:
        print("⚠️ User declined - proceeding unsigned")
        return {
            "content": content,
            "signature": None,
            "signed": False,
            "reason": "user_declined",
        }


def logging_pattern():
    """
    Structured logging for production systems.
    """
    import logging
    
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("vouch-app")
    
    client = VouchClient()
    
    try:
        result = client.sign("Logged content", origin="logging-demo")
        logger.info("Signature succeeded", extra={
            "signature": result["signature"][:32],
            "did": result.get("did"),
        })
        
    except VouchConnectionError as e:
        logger.error("Vouch daemon connection failed", extra={
            "error_type": "connection",
            "error": str(e),
        })
        
    except NoKeysConfiguredError as e:
        logger.warning("Vouch identity not configured", extra={
            "error_type": "no_keys",
            "error": str(e),
        })
        
    except UserDeniedSignatureError as e:
        logger.info("User declined to sign", extra={
            "error_type": "user_denied",
            "error": str(e),
        })


def context_manager_pattern():
    """
    Using context managers for cleanup.
    """
    from contextlib import contextmanager
    
    @contextmanager
    def vouch_signing_context(origin: str):
        """Context manager that handles Vouch errors gracefully."""
        client = VouchClient()
        
        try:
            # Check connection first
            client.connect()
            yield client
            
        except VouchConnectionError:
            print(f"⚠️ [{origin}] Daemon offline")
            yield None
            
        except VouchError as e:
            print(f"⚠️ [{origin}] Vouch error: {e}")
            yield None
    
    # Usage
    with vouch_signing_context("context-demo") as client:
        if client:
            try:
                client.sign("Content", origin="context-demo")
                print("✅ Signed with context manager")
            except UserDeniedSignatureError:
                print("⚠️ User denied")
        else:
            print("Proceeding without Vouch")


def file_error_handling():
    """
    Error handling specific to file operations.
    """
    client = VouchClient()
    
    file_path = "/path/to/nonexistent/file.txt"
    
    try:
        client.sign_file(file_path, origin="file-error-demo")
        
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        
    except PermissionError:
        print(f"❌ Permission denied: {file_path}")
        
    except IsADirectoryError:
        print(f"❌ Is a directory, not a file: {file_path}")
        
    except VouchConnectionError:
        print("❌ Daemon offline")


def main():
    print("\n🛡️ Example 1: Basic error handling")
    basic_error_handling()
    
    print("\n🛡️ Example 2: Hierarchical error handling")
    hierarchical_error_handling()
    
    print("\n🛡️ Example 3: Fallback pattern")
    result = fallback_pattern()
    print(f"   Result: signed={result['signed']}")
    
    print("\n🛡️ Example 4: Context manager pattern")
    context_manager_pattern()
    
    print("\n🛡️ Example 5: File error handling")
    file_error_handling()


if __name__ == "__main__":
    main()
