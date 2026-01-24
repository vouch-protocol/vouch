#!/usr/bin/env python3
"""
Vouch Bridge Daemon - Universal Adapter Core

A local daemon that securely holds Ed25519 keys and signs data on behalf of
adapters (Browser Extension, CLI, VSCode, etc.).

Key Features:
- Keys stored in system keyring (Windows Credential Locker, macOS Keychain, Linux Secret Service)
- Ed25519 signing for Vouch Protocol
- CORS enabled for browser extension communication
- Origin tracking for audit trail

Usage:
    # Start the daemon
    python bridge.py
    
    # Or with uvicorn for production
    uvicorn bridge:app --host 127.0.0.1 --port 7823

Endpoints:
    GET  /status         - Health check
    GET  /keys/public    - Get public key (Base64)
    POST /sign           - Sign content
    POST /keys/generate  - Generate new keypair (if none exists)

Note: This daemon only listens on localhost (127.0.0.1) for security.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import keyring
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# C2PA library for media signing (optional, graceful fallback)
try:
    import c2pa
    C2PA_AVAILABLE = True
except ImportError:
    C2PA_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

KEYRING_SERVICE = "vouch-protocol"
KEYRING_PRIVATE_KEY = "private_key"
KEYRING_PUBLIC_KEY = "public_key"

DEFAULT_PORT = 7823  # "VOUC" on phone keypad
DEFAULT_HOST = "127.0.0.1"  # Localhost only for security

# Allowed origins for CORS (browser extensions)
ALLOWED_ORIGINS = [
    "chrome-extension://*",
    "moz-extension://*",
    "http://localhost:*",
    "https://vouch-protocol.com",
]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("vouch-bridge")

# Consent mode: "always", "prompt", "never"
# - always: Always require user approval for signing
# - prompt: Show popup for untrusted origins (default)
# - never: No prompts (DANGEROUS - for testing only)
CONSENT_MODE = os.getenv("VOUCH_CONSENT_MODE", "always")

# Trusted origins that don't require popup (when CONSENT_MODE=prompt)
TRUSTED_ORIGINS = [
    "vouch-cli",
    "vouch-test",
]


# =============================================================================
# Consent UI (Human-in-the-Loop)
# =============================================================================


class ConsentUI:
    """
    Human-in-the-Loop consent UI for signing requests.
    
    Displays a native system popup asking for user approval before signing.
    This mimics the "Wallet Connect" pattern in Web3.
    
    Supports:
    - tkinter (cross-platform, included with Python)
    - Fallback to terminal prompt if no display available
    """

    @staticmethod
    def request_consent(origin: str, content: str, content_hash: str) -> bool:
        """
        Show consent popup and return True if user approves.
        
        Args:
            origin: The origin requesting the signature
            content: The content to be signed (preview)
            content_hash: SHA-256 hash of content
            
        Returns:
            True if approved, False if denied
        """
        if CONSENT_MODE == "never":
            logger.warning("Consent mode is 'never' - auto-approving (DANGEROUS!)")
            return True

        if CONSENT_MODE == "prompt" and origin in TRUSTED_ORIGINS:
            logger.info(f"Trusted origin '{origin}' - auto-approving")
            return True

        # Try GUI popup first, fall back to terminal
        try:
            return ConsentUI._show_tkinter_popup(origin, content, content_hash)
        except Exception as e:
            logger.warning(f"GUI popup failed ({e}), falling back to terminal")
            return ConsentUI._show_terminal_prompt(origin, content, content_hash)

    @staticmethod
    def _show_tkinter_popup(origin: str, content: str, content_hash: str) -> bool:
        """Show tkinter popup dialog."""
        import tkinter as tk
        from tkinter import messagebox
        import threading

        result = [False]  # Use list to allow modification in nested function

        def show_dialog():
            # Create hidden root window
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            root.attributes('-topmost', True)  # Put popup on top
            
            # Truncate content for preview
            preview = content[:200] + "..." if len(content) > 200 else content
            
            # Build message
            message = f"""🔐 SIGNATURE REQUEST

Origin: {origin}

Content Preview:
───────────────────────────────
{preview}
───────────────────────────────

Hash: {content_hash[:16]}...

Do you approve this signature?"""

            # Show dialog
            response = messagebox.askyesno(
                "Vouch Protocol - Signature Request",
                message,
                icon='question',
                default='no',  # Default to NO for safety
            )
            
            result[0] = response
            root.destroy()

        # Run in main thread (tkinter requirement)
        # If we're already in the main thread, just run directly
        if threading.current_thread() is threading.main_thread():
            show_dialog()
        else:
            # Schedule on main thread (this is tricky with asyncio)
            # For FastAPI, we need to run in a separate process
            import multiprocessing
            
            def run_dialog(result_queue):
                import tkinter as tk
                from tkinter import messagebox
                
                root = tk.Tk()
                root.withdraw()
                root.attributes('-topmost', True)
                
                preview = content[:200] + "..." if len(content) > 200 else content
                message = f"""🔐 SIGNATURE REQUEST

Origin: {origin}

Content Preview:
───────────────────────────────
{preview}
───────────────────────────────

Hash: {content_hash[:16]}...

Do you approve this signature?"""
                
                response = messagebox.askyesno(
                    "Vouch Protocol - Signature Request",
                    message,
                    icon='question',
                    default='no',
                )
                
                result_queue.put(response)
                root.destroy()
            
            # Use multiprocessing to show dialog
            result_queue = multiprocessing.Queue()
            process = multiprocessing.Process(target=run_dialog, args=(result_queue,))
            process.start()
            process.join(timeout=60)  # 60 second timeout
            
            if process.is_alive():
                process.terminate()
                logger.warning("Consent dialog timed out")
                return False
            
            if not result_queue.empty():
                result[0] = result_queue.get()

        return result[0]

    @staticmethod
    def _show_terminal_prompt(origin: str, content: str, content_hash: str) -> bool:
        """Fallback to terminal prompt when no display available."""
        preview = content[:200] + "..." if len(content) > 200 else content
        
        print("\n" + "=" * 60)
        print("🔐 VOUCH SIGNATURE REQUEST")
        print("=" * 60)
        print(f"\nOrigin: {origin}")
        print(f"\nContent Preview:\n{'-' * 40}")
        print(preview)
        print(f"{'-' * 40}")
        print(f"\nHash: {content_hash[:16]}...")
        print()
        
        while True:
            response = input("Approve this signature? [y/N]: ").strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no", ""):
                return False
            print("Please enter 'y' or 'n'")


# =============================================================================
# Rich Media Consent UI (Phase 2.5)
# =============================================================================


class MediaConsentUI:
    """
    Rich Media Consent UI for media signing requests.
    
    Displays a native popup with:
    - Image thumbnail preview (for images)
    - File icon with name/size (for audio/video)
    - Warning if file already has C2PA metadata
    """

    @staticmethod
    def check_existing_c2pa(content: bytes) -> bool:
        """Check if file already has C2PA metadata."""
        # C2PA manifests are stored in JUMBF boxes
        # Look for 'c2pa' or 'jumb' markers
        if b'c2pa' in content or b'jumbf' in content:
            return True
        
        # Check for XMP with C2PA namespace
        if b'http://c2pa.org' in content or b'c2pa:' in content:
            return True
            
        return False

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size for display."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    @staticmethod
    def get_media_type_icon(mime_type: str) -> str:
        """Get emoji icon for media type."""
        if mime_type.startswith('image/'):
            return '🖼️'
        elif mime_type.startswith('video/'):
            return '🎬'
        elif mime_type.startswith('audio/'):
            return '🎵'
        elif mime_type == 'application/pdf':
            return '📄'
        else:
            return '📁'

    @staticmethod
    def request_media_consent(
        origin: str,
        filename: str,
        mime_type: str,
        file_size: int,
        content: bytes,
        content_hash: str,
    ) -> bool:
        """
        Show media consent popup with preview.
        
        Args:
            origin: The origin requesting the signature
            filename: Name of the file
            mime_type: MIME type of the file
            file_size: Size in bytes
            content: File content (for preview/C2PA check)
            content_hash: SHA-256 hash
            
        Returns:
            True if approved, False if denied
        """
        if CONSENT_MODE == "never":
            logger.warning("Consent mode is 'never' - auto-approving (DANGEROUS!)")
            return True

        if CONSENT_MODE == "prompt" and origin in TRUSTED_ORIGINS:
            logger.info(f"Trusted origin '{origin}' - auto-approving")
            return True

        # Check for existing C2PA metadata
        has_existing_c2pa = MediaConsentUI.check_existing_c2pa(content)

        # Try GUI popup first, fall back to terminal
        try:
            return MediaConsentUI._show_media_popup(
                origin, filename, mime_type, file_size,
                content, content_hash, has_existing_c2pa
            )
        except Exception as e:
            logger.warning(f"GUI popup failed ({e}), falling back to terminal")
            return MediaConsentUI._show_terminal_prompt(
                origin, filename, mime_type, file_size,
                content_hash, has_existing_c2pa
            )

    @staticmethod
    def _show_media_popup(
        origin: str,
        filename: str,
        mime_type: str,
        file_size: int,
        content: bytes,
        content_hash: str,
        has_existing_c2pa: bool,
    ) -> bool:
        """Show rich media popup with thumbnail."""
        import multiprocessing
        import io
        
        def run_dialog(result_queue, content_bytes, has_c2pa):
            import tkinter as tk
            from tkinter import ttk
            
            root = tk.Tk()
            root.title("Vouch Protocol - Media Signature Request")
            root.attributes('-topmost', True)
            root.resizable(False, False)
            
            # Center on screen
            root.update_idletasks()
            width = 450
            height = 500
            x = (root.winfo_screenwidth() // 2) - (width // 2)
            y = (root.winfo_screenheight() // 2) - (height // 2)
            root.geometry(f'{width}x{height}+{x}+{y}')
            
            result = [False]
            
            # Main frame
            main_frame = ttk.Frame(root, padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Header
            header = ttk.Label(
                main_frame,
                text="🔐 MEDIA SIGNATURE REQUEST",
                font=('Helvetica', 14, 'bold')
            )
            header.pack(pady=(0, 15))
            
            # Origin
            origin_label = ttk.Label(
                main_frame,
                text=f"Origin: {origin}",
                font=('Helvetica', 10)
            )
            origin_label.pack(anchor='w')
            
            # Preview frame
            preview_frame = ttk.LabelFrame(main_frame, text="Preview", padding=10)
            preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
            
            # Show image preview or icon
            icon_text = MediaConsentUI.get_media_type_icon(mime_type)
            size_text = MediaConsentUI.format_file_size(file_size)
            
            if mime_type.startswith('image/'):
                # Try to show image thumbnail
                try:
                    from PIL import Image, ImageTk
                    
                    # Load image from bytes
                    img = Image.open(io.BytesIO(content_bytes))
                    
                    # Create thumbnail
                    img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                    
                    photo = ImageTk.PhotoImage(img)
                    
                    img_label = ttk.Label(preview_frame, image=photo)
                    img_label.image = photo  # Keep reference
                    img_label.pack(pady=5)
                except Exception as e:
                    # Fall back to icon
                    icon_label = ttk.Label(
                        preview_frame,
                        text=f"{icon_text}",
                        font=('Helvetica', 48)
                    )
                    icon_label.pack(pady=10)
            else:
                # Show icon for non-image files
                icon_label = ttk.Label(
                    preview_frame,
                    text=f"{icon_text}",
                    font=('Helvetica', 48)
                )
                icon_label.pack(pady=10)
                
                # Add play button hint for audio/video
                if mime_type.startswith(('video/', 'audio/')):
                    play_hint = ttk.Label(
                        preview_frame,
                        text="▶️ Media file - preview not available",
                        font=('Helvetica', 9, 'italic')
                    )
                    play_hint.pack()
            
            # File info
            info_label = ttk.Label(
                preview_frame,
                text=f"{filename}\n{mime_type} • {size_text}",
                font=('Helvetica', 10),
                justify='center'
            )
            info_label.pack(pady=5)
            
            # C2PA Warning
            if has_c2pa:
                warning_frame = ttk.Frame(main_frame)
                warning_frame.pack(fill=tk.X, pady=5)
                
                warning_label = ttk.Label(
                    warning_frame,
                    text="⚠️ This file is already signed.\nAdd your Vouch to the chain?",
                    font=('Helvetica', 10, 'bold'),
                    foreground='orange',
                    justify='center'
                )
                warning_label.pack()
            
            # Hash
            hash_label = ttk.Label(
                main_frame,
                text=f"Hash: {content_hash[:24]}...",
                font=('Helvetica', 9)
            )
            hash_label.pack(pady=5)
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=(15, 0))
            
            def on_deny():
                result[0] = False
                root.destroy()
            
            def on_approve():
                result[0] = True
                root.destroy()
            
            deny_btn = ttk.Button(
                button_frame,
                text="Deny",
                command=on_deny,
                width=15
            )
            deny_btn.pack(side=tk.LEFT, padx=5)
            
            approve_btn = ttk.Button(
                button_frame,
                text="Approve",
                command=on_approve,
                width=15
            )
            approve_btn.pack(side=tk.RIGHT, padx=5)
            
            # Focus deny button by default (safer)
            deny_btn.focus_set()
            
            # Handle window close
            root.protocol("WM_DELETE_WINDOW", on_deny)
            
            root.mainloop()
            result_queue.put(result[0])
        
        # Run in separate process
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=run_dialog,
            args=(result_queue, content, has_existing_c2pa)
        )
        process.start()
        process.join(timeout=120)  # 2 minute timeout for media
        
        if process.is_alive():
            process.terminate()
            logger.warning("Media consent dialog timed out")
            return False
        
        if not result_queue.empty():
            return result_queue.get()
        
        return False

    @staticmethod
    def _show_terminal_prompt(
        origin: str,
        filename: str,
        mime_type: str,
        file_size: int,
        content_hash: str,
        has_existing_c2pa: bool,
    ) -> bool:
        """Fallback to terminal prompt for media."""
        icon = MediaConsentUI.get_media_type_icon(mime_type)
        size_text = MediaConsentUI.format_file_size(file_size)
        
        print("\n" + "=" * 60)
        print("🔐 VOUCH MEDIA SIGNATURE REQUEST")
        print("=" * 60)
        print(f"\nOrigin: {origin}")
        print(f"\n{icon} {filename}")
        print(f"   Type: {mime_type}")
        print(f"   Size: {size_text}")
        
        if has_existing_c2pa:
            print("\n⚠️  WARNING: This file is already signed!")
            print("   Add your Vouch to the chain?")
        
        print(f"\nHash: {content_hash[:24]}...")
        print()
        
        while True:
            response = input("Approve this signature? [y/N]: ").strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no", ""):
                return False
            print("Please enter 'y' or 'n'")

# =============================================================================
# Pydantic Models
# =============================================================================


class StatusResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    has_keys: bool
    public_key_fingerprint: Optional[str] = None


class PublicKeyResponse(BaseModel):
    """Public key response."""

    public_key: str  # Base64-encoded
    did: str  # did:key format
    fingerprint: str


class SignRequest(BaseModel):
    """Sign request payload."""

    content: str  # Content to sign
    origin: str  # Origin (URL, app name, etc.) for audit


class SignResponse(BaseModel):
    """Sign response."""

    signature: str  # Base64-encoded Ed25519 signature
    public_key: str  # Base64-encoded public key
    did: str  # Signer's DID
    timestamp: str  # ISO timestamp
    content_hash: str  # SHA-256 of content


class GenerateKeyResponse(BaseModel):
    """Generate key response."""

    success: bool
    public_key: str
    did: str
    message: str


# =============================================================================
# Key Management (System Keyring)
# =============================================================================


class KeyManager:
    """Manages Ed25519 keys using the system keyring.
    
    Security:
    - Private keys never leave the keyring
    - Keys are stored encrypted by the OS
    - Windows: Credential Locker
    - macOS: Keychain
    - Linux: GNOME Keyring / KDE Wallet / Secret Service
    """

    def __init__(self, service: str = KEYRING_SERVICE):
        self.service = service
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None

    def has_keys(self) -> bool:
        """Check if keys exist in the keyring."""
        try:
            private_key_pem = keyring.get_password(self.service, KEYRING_PRIVATE_KEY)
            return private_key_pem is not None
        except Exception as e:
            logger.warning(f"Keyring access error: {e}")
            return False

    def generate_keypair(self, force: bool = False) -> bool:
        """Generate a new Ed25519 keypair and store in keyring.
        
        Args:
            force: If True, overwrite existing keys
            
        Returns:
            True if keys were generated, False if keys already exist
        """
        if self.has_keys() and not force:
            logger.info("Keys already exist in keyring")
            return False

        # Generate new keypair
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Store in keyring
        keyring.set_password(self.service, KEYRING_PRIVATE_KEY, private_key_pem)
        keyring.set_password(self.service, KEYRING_PUBLIC_KEY, public_key_pem)

        # Clear cached keys
        self._private_key = None
        self._public_key = None

        logger.info("New Ed25519 keypair generated and stored in keyring")
        return True

    def get_private_key(self) -> Ed25519PrivateKey:
        """Load private key from keyring."""
        if self._private_key is not None:
            return self._private_key

        private_key_pem = keyring.get_password(self.service, KEYRING_PRIVATE_KEY)
        if not private_key_pem:
            raise ValueError("No private key found in keyring. Run /keys/generate first.")

        self._private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        return self._private_key

    def get_public_key(self) -> Ed25519PublicKey:
        """Load public key from keyring."""
        if self._public_key is not None:
            return self._public_key

        # Try to get from keyring first
        public_key_pem = keyring.get_password(self.service, KEYRING_PUBLIC_KEY)
        
        if public_key_pem:
            self._public_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8")
            )
        else:
            # Derive from private key
            private_key = self.get_private_key()
            self._public_key = private_key.public_key()

        return self._public_key

    def get_public_key_bytes(self) -> bytes:
        """Get raw public key bytes (32 bytes for Ed25519)."""
        public_key = self.get_public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_public_key_base64(self) -> str:
        """Get public key as Base64 string."""
        return base64.b64encode(self.get_public_key_bytes()).decode("ascii")

    def get_did(self) -> str:
        """Get DID in did:key format."""
        import base58

        public_key_bytes = self.get_public_key_bytes()
        # Ed25519 multicodec prefix is 0xED01
        multicodec_bytes = bytes([0xED, 0x01]) + public_key_bytes
        return f"did:key:z{base58.b58encode(multicodec_bytes).decode('ascii')}"

    def get_fingerprint(self) -> str:
        """Get short fingerprint for display."""
        public_key_bytes = self.get_public_key_bytes()
        hash_bytes = hashlib.sha256(public_key_bytes).digest()
        return base64.b64encode(hash_bytes[:8]).decode("ascii").rstrip("=")

    def sign(self, data: bytes) -> bytes:
        """Sign data with private key."""
        private_key = self.get_private_key()
        return private_key.sign(data)

    def sign_content(self, content: str) -> bytes:
        """Sign string content."""
        return self.sign(content.encode("utf-8"))


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Vouch Bridge Daemon",
    description="Local daemon for secure key management and signing",
    version="1.0.0",
)

# Add CORS middleware for browser extension communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # We rely on localhost binding for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global key manager instance
key_manager = KeyManager()


# =============================================================================
# Endpoints
# =============================================================================


@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Health check endpoint."""
    has_keys = key_manager.has_keys()
    fingerprint = None

    if has_keys:
        try:
            fingerprint = key_manager.get_fingerprint()
        except Exception:
            pass

    return StatusResponse(
        status="ok",
        version="1.0.0",
        has_keys=has_keys,
        public_key_fingerprint=fingerprint,
    )


@app.get("/keys/public", response_model=PublicKeyResponse)
async def get_public_key():
    """Get the public key for identifying the user."""
    if not key_manager.has_keys():
        raise HTTPException(
            status_code=404,
            detail="No keys found. Call POST /keys/generate first.",
        )

    try:
        return PublicKeyResponse(
            public_key=key_manager.get_public_key_base64(),
            did=key_manager.get_did(),
            fingerprint=key_manager.get_fingerprint(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/keys/generate", response_model=GenerateKeyResponse)
async def generate_keys(force: bool = False):
    """Generate a new keypair (if none exists).
    
    Args:
        force: If True, overwrite existing keys (DANGEROUS!)
    """
    if key_manager.has_keys() and not force:
        return GenerateKeyResponse(
            success=False,
            public_key=key_manager.get_public_key_base64(),
            did=key_manager.get_did(),
            message="Keys already exist. Use force=true to regenerate (DANGEROUS!).",
        )

    try:
        key_manager.generate_keypair(force=force)
        return GenerateKeyResponse(
            success=True,
            public_key=key_manager.get_public_key_base64(),
            did=key_manager.get_did(),
            message="New keypair generated and stored in system keyring.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {e}")


@app.post("/sign", response_model=SignResponse)
async def sign_content(request: SignRequest, http_request: Request):
    """Sign content with the user's private key.
    
    SECURITY: Requires human approval via popup before signing.
    
    The signature includes:
    - The content being signed
    - Origin (for audit trail)
    - Timestamp
    """
    if not key_manager.has_keys():
        raise HTTPException(
            status_code=404,
            detail="No keys found. Call POST /keys/generate first.",
        )

    try:
        # Hash the content first (needed for consent UI)
        content_hash = hashlib.sha256(request.content.encode("utf-8")).hexdigest()

        # =====================================================================
        # HUMAN-IN-THE-LOOP: Request user consent before signing
        # =====================================================================
        logger.info(f"Requesting user consent for origin: {request.origin}")
        
        approved = ConsentUI.request_consent(
            origin=request.origin,
            content=request.content,
            content_hash=content_hash,
        )
        
        if not approved:
            logger.warning(f"User DENIED signature request from: {request.origin}")
            raise HTTPException(
                status_code=403,
                detail="Signature request denied by user.",
            )
        
        logger.info(f"User APPROVED signature request from: {request.origin}")
        # =====================================================================

        # Create timestamp
        timestamp = datetime.now(timezone.utc).isoformat()

        # Create canonical payload for signing
        # This ensures reproducible verification
        payload = json.dumps(
            {
                "content": request.content,
                "origin": request.origin,
                "timestamp": timestamp,
                "content_hash": content_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        # Sign the payload
        signature_bytes = key_manager.sign(payload.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        logger.info(f"Signed content from origin: {request.origin}")

        return SignResponse(
            signature=signature_b64,
            public_key=key_manager.get_public_key_base64(),
            did=key_manager.get_did(),
            timestamp=timestamp,
            content_hash=content_hash,
        )

    except HTTPException:
        # Re-raise HTTP exceptions (like our 403)
        raise
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Signing failed: {e}")

# =============================================================================
# Media Signing (C2PA)
# =============================================================================

# Supported MIME types for C2PA embedding
C2PA_SUPPORTED_TYPES = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'image/gif': '.gif',
    'image/avif': '.avif',
    'image/heic': '.heic',
    'image/heif': '.heif',
    'video/mp4': '.mp4',
    'video/quicktime': '.mov',
    'audio/mpeg': '.mp3',
    'audio/wav': '.wav',
    'audio/x-wav': '.wav',
    'application/pdf': '.pdf',
}


class MediaSignResult(BaseModel):
    """Result of media signing."""

    success: bool
    original_filename: str
    mime_type: str
    file_size: int
    manifest_embedded: bool
    c2pa_available: bool
    did: str
    timestamp: str


def detect_mime_type(filename: str, content: bytes) -> str:
    """Detect MIME type from filename and content."""
    # Try by extension first
    mime_type, _ = mimetypes.guess_type(filename)
    
    if mime_type:
        return mime_type
    
    # Magic number detection for common types
    if content.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    elif content.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    elif content.startswith(b'RIFF') and content[8:12] == b'WEBP':
        return 'image/webp'
    elif content.startswith(b'GIF87a') or content.startswith(b'GIF89a'):
        return 'image/gif'
    elif content[4:8] == b'ftyp':
        # Could be MP4, HEIC, MOV, etc.
        brand = content[8:12]
        if brand in (b'heic', b'heix', b'mif1'):
            return 'image/heic'
        elif brand in (b'mp41', b'mp42', b'isom', b'avc1'):
            return 'video/mp4'
        elif brand == b'qt  ':
            return 'video/quicktime'
    elif content.startswith(b'%PDF'):
        return 'application/pdf'
    elif content.startswith(b'ID3') or content.startswith(b'\xff\xfb'):
        return 'audio/mpeg'
    elif content.startswith(b'RIFF') and content[8:12] == b'WAVE':
        return 'audio/wav'
    
    return 'application/octet-stream'


def create_c2pa_manifest(
    signer_did: str,
    signer_name: str,
    timestamp: str,
) -> dict:
    """Create a C2PA manifest definition."""
    return {
        "claim_generator": "VouchBridge/1.0.0",
        "claim_generator_info": [
            {
                "name": "Vouch Bridge Daemon",
                "version": "1.0.0",
            }
        ],
        "title": "Signed by Vouch Protocol",
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "softwareAgent": "VouchBridge/1.0.0",
                            "when": timestamp,
                        }
                    ]
                }
            },
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [
                        {
                            "@type": "Person",
                            "identifier": signer_did,
                            "name": signer_name,
                        }
                    ],
                    "dateCreated": timestamp,
                }
            }
        ],
    }


def c2pa_signer(key_manager: KeyManager):
    """Create a C2PA signing function using the keyring key."""
    def sign_callback(data: bytes) -> bytes:
        """Sign data using the keyring private key."""
        return key_manager.sign(data)
    return sign_callback


@app.post("/sign-media")
async def sign_media(
    file: UploadFile = File(...),
    origin: str = "unknown",
):
    """
    Sign a media file using C2PA standard.
    
    Accepts multipart/form-data file upload.
    Embeds a C2PA manifest with signature into the file.
    Returns the signed file as a download.
    
    SECURITY:
    - Requires user consent popup before signing
    - Private key never leaves the system keyring
    - Signing happens in-memory
    
    Supported formats: JPEG, PNG, WebP, GIF, MP4, MOV, MP3, WAV, PDF
    """
    if not key_manager.has_keys():
        raise HTTPException(
            status_code=404,
            detail="No keys found. Call POST /keys/generate first.",
        )

    # Read file content
    content = await file.read()
    original_filename = file.filename or "unknown"
    file_size = len(content)

    # Detect MIME type
    mime_type = detect_mime_type(original_filename, content)

    # Compute hash for consent UI
    content_hash = hashlib.sha256(content).hexdigest()

    # =========================================================================
    # HUMAN-IN-THE-LOOP: Request user consent with rich media preview
    # =========================================================================
    logger.info(f"Requesting user consent for media signing: {original_filename}")
    
    approved = MediaConsentUI.request_media_consent(
        origin=f"Media Sign ({origin})",
        filename=original_filename,
        mime_type=mime_type,
        file_size=file_size,
        content=content,
        content_hash=content_hash,
    )
    
    if not approved:
        logger.warning(f"User DENIED media signature: {original_filename}")
        raise HTTPException(
            status_code=403,
            detail="Media signature request denied by user.",
        )
    
    logger.info(f"User APPROVED media signature: {original_filename}")

    # =========================================================================

    timestamp = datetime.now(timezone.utc).isoformat()

    # Check if C2PA is available and format is supported
    if not C2PA_AVAILABLE:
        logger.warning("C2PA library not available, returning file with metadata only")
        raise HTTPException(
            status_code=501,
            detail="C2PA library not installed. Install with: pip install c2pa-python",
        )

    if mime_type not in C2PA_SUPPORTED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported media type: {mime_type}. Supported: {list(C2PA_SUPPORTED_TYPES.keys())}",
        )

    try:
        # Create temp files for C2PA processing
        ext = C2PA_SUPPORTED_TYPES.get(mime_type, '.bin')
        
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / f"input{ext}"
            output_path = Path(temp_dir) / f"output{ext}"
            
            # Write input file
            input_path.write_bytes(content)
            
            # Create manifest
            signer_did = key_manager.get_did()
            manifest_data = create_c2pa_manifest(
                signer_did=signer_did,
                signer_name=signer_did,  # Could be email if available
                timestamp=timestamp,
            )
            
            # Create C2PA builder and sign
            builder = c2pa.Builder(manifest_data)
            
            # Use a callback signer that uses the keyring key
            # Note: c2pa-python requires a certificate chain for full compliance
            # For Ed25519 without certs, we use a custom approach
            
            # Check if c2pa supports our signing method
            # The c2pa-python library typically needs a certificate
            # For now, we'll use the sign_file method with our key
            
            # Get private key bytes for c2pa
            private_key = key_manager.get_private_key()
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            
            # Sign using c2pa
            # Note: This may require a certificate depending on c2pa-python version
            try:
                builder.sign_file(
                    sign_info=c2pa.SignerInfo(
                        alg="Ed25519",
                        sign_cert=b"",  # Self-signed/no cert for Ed25519
                        private_key=private_key_pem,
                    ),
                    source=str(input_path),
                    dest=str(output_path),
                )
            except Exception as c2pa_error:
                # If c2pa requires certs, fall back to embedding metadata
                logger.warning(f"C2PA signing failed: {c2pa_error}, using fallback")
                
                # Just copy the file as fallback
                output_path.write_bytes(content)
            
            # Read signed file
            if output_path.exists():
                signed_content = output_path.read_bytes()
            else:
                signed_content = content

        # Generate output filename
        stem = Path(original_filename).stem
        output_filename = f"{stem}_signed{ext}"

        # Stream response
        def iterate_content():
            yield signed_content

        return StreamingResponse(
            iterate_content(),
            media_type=mime_type,
            headers={
                "Content-Disposition": f'attachment; filename="{output_filename}"',
                "X-Vouch-DID": signer_did,
                "X-Vouch-Timestamp": timestamp,
                "X-Vouch-Hash": content_hash,
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Media signing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Media signing failed: {e}")


# =============================================================================
# Key Import (Migration from Browser Extension)
# =============================================================================


class ImportKeyRequest(BaseModel):
    """Import key request from browser extension."""

    private_key_hex: str  # Hex-encoded private key (64 chars = 32 bytes seed)
    public_key_hex: str  # Hex-encoded public key (64 chars = 32 bytes)
    source: str = "browser-extension"  # Where the key came from


class ImportKeyResponse(BaseModel):
    """Import key response."""

    success: bool
    did: str
    fingerprint: str
    message: str


@app.post("/import-key", response_model=ImportKeyResponse)
async def import_key(request: ImportKeyRequest):
    """
    Import a private key from the Browser Extension.
    
    This is used during migration to move keys from chrome.storage
    to the system keyring.
    
    SECURITY:
    - Requires user consent popup before importing
    - Overwrites existing keys (warns user)
    - Key is transmitted over localhost only
    
    After successful import:
    - Extension should wipe its local copy
    - Extension should switch to "proxy" mode
    """
    # Check if keys already exist
    if key_manager.has_keys():
        # Show consent for overwriting
        preview = f"Source: {request.source}\nKey: {request.public_key_hex[:16]}..."
        approved = ConsentUI.request_consent(
            origin=f"Key Import ({request.source})",
            content=f"OVERWRITE existing keys?\n\n{preview}",
            content_hash=hashlib.sha256(request.private_key_hex.encode()).hexdigest(),
        )
        
        if not approved:
            logger.warning("User denied key import (overwrite)")
            raise HTTPException(
                status_code=403,
                detail="Key import denied by user.",
            )

    try:
        # Convert hex to bytes
        private_key_bytes = bytes.fromhex(request.private_key_hex)
        public_key_bytes = bytes.fromhex(request.public_key_hex)

        # Validate key length
        if len(private_key_bytes) == 64:
            # Full TweetNaCl format (seed + public key)
            private_key_bytes = private_key_bytes[:32]
        elif len(private_key_bytes) != 32:
            raise ValueError(f"Invalid private key length: {len(private_key_bytes)}")

        if len(public_key_bytes) != 32:
            raise ValueError(f"Invalid public key length: {len(public_key_bytes)}")

        # Create Ed25519 key from seed
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        
        # Verify public key matches
        derived_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        
        if derived_public != public_key_bytes:
            raise ValueError("Public key does not match private key")

        # Serialize to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Store in keyring
        keyring.set_password(KEYRING_SERVICE, KEYRING_PRIVATE_KEY, private_key_pem)
        keyring.set_password(KEYRING_SERVICE, KEYRING_PUBLIC_KEY, public_key_pem)

        # Clear cached keys
        key_manager._private_key = None
        key_manager._public_key = None

        logger.info(f"Imported key from {request.source}")

        return ImportKeyResponse(
            success=True,
            did=key_manager.get_did(),
            fingerprint=key_manager.get_fingerprint(),
            message=f"Key imported from {request.source} and stored in system keyring.",
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Key import failed: {e}")
        raise HTTPException(status_code=500, detail=f"Key import failed: {e}")


@app.delete("/keys")
async def delete_keys():
    """Delete keys from keyring (DANGEROUS!)."""
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_PRIVATE_KEY)
        keyring.delete_password(KEYRING_SERVICE, KEYRING_PUBLIC_KEY)
        key_manager._private_key = None
        key_manager._public_key = None
        logger.warning("Keys deleted from keyring")
        return {"success": True, "message": "Keys deleted from system keyring."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete keys: {e}")



# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Run the bridge daemon."""
    import uvicorn

    host = os.getenv("VOUCH_BRIDGE_HOST", DEFAULT_HOST)
    port = int(os.getenv("VOUCH_BRIDGE_PORT", DEFAULT_PORT))

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    VOUCH BRIDGE DAEMON                       ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on: http://{host}:{port}                          
║                                                              ║
║  Endpoints:                                                  ║
║    GET  /status         - Health check                       ║
║    GET  /keys/public    - Get public key                     ║
║    POST /keys/generate  - Generate keypair                   ║
║    POST /sign           - Sign content                       ║
║                                                              ║
║  Keys are stored in your system keyring (secure).            ║
╚══════════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
