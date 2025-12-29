"""
Vouch Protocol Command Line Interface.

Provides commands for initializing identity, signing messages, and verifying tokens.
"""

import argparse
import sys
import json
import os
import logging

from jwcrypto import jwk

from vouch.signer import Signer
from vouch.verifier import Verifier


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def cmd_init(args: argparse.Namespace) -> int:
    """Generate a new Ed25519 keypair for agent identity."""
    try:
        # Generate Ed25519 key
        key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        
        # Export keys
        private_key = key.export_private()
        public_key = key.export_public()
        
        # Build DID
        domain = args.domain if args.domain else "example.com"
        did = f"did:web:{domain}"
        
        if args.env:
            # Output as environment variable format
            print(f"export VOUCH_DID='{did}'")
            print(f"export VOUCH_PRIVATE_KEY='{private_key}'")
            print(f"# Public Key (for vouch.json): {public_key}", file=sys.stderr)
        else:
            print("🔑 NEW AGENT IDENTITY GENERATED\n")
            print(f"DID: {did}")
            print("\n--- PRIVATE KEY (Keep Secret / Set as Env Var) ---")
            print(private_key)
            print("\n--- PUBLIC KEY (Put this in vouch.json) ---")
            print(public_key)
        
        return 0
        
    except Exception as e:
        print(f"Error generating keys: {e}", file=sys.stderr)
        return 1


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a message or JSON payload."""
    # Get credentials
    private_key = args.key or os.environ.get('VOUCH_PRIVATE_KEY')
    did = args.did or os.environ.get('VOUCH_DID')
    
    if not private_key:
        print("Error: Missing private key. Set VOUCH_PRIVATE_KEY or use --key", file=sys.stderr)
        return 1
    
    if not did:
        print("Error: Missing DID. Set VOUCH_DID or use --did", file=sys.stderr)
        return 1
    
    try:
        # Parse the message
        if args.json:
            try:
                payload = json.loads(args.message)
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON message: {e}", file=sys.stderr)
                return 1
        else:
            # Wrap string message in a payload
            payload = {"message": args.message}
        
        # Create signer and sign
        signer = Signer(private_key=private_key, did=did)
        token = signer.sign(payload)
        
        if args.header:
            print(f"Vouch-Token: {token}")
        else:
            print(token)
        
        return 0
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error signing message: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a Vouch-Token."""
    token = args.token
    public_key = args.key or os.environ.get('VOUCH_PUBLIC_KEY')
    
    try:
        if public_key:
            valid, passport = Verifier.verify(token, public_key_jwk=public_key)
        else:
            # Verify without signature check (structure only)
            valid, passport = Verifier.verify(token)
            if valid:
                print("⚠️  Warning: No public key provided, signature not verified", file=sys.stderr)
        
        if valid and passport:
            if args.json:
                result = {
                    "valid": True,
                    "sub": passport.sub,
                    "iss": passport.iss,
                    "iat": passport.iat,
                    "exp": passport.exp,
                    "jti": passport.jti,
                    "payload": passport.payload
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"✅ VALID")
                print(f"   Subject: {passport.sub}")
                print(f"   Issuer:  {passport.iss}")
                print(f"   Payload: {json.dumps(passport.payload)}")
            return 0
        else:
            if args.json:
                print(json.dumps({"valid": False}))
            else:
                print("❌ INVALID")
            return 1
            
    except Exception as e:
        print(f"Error verifying token: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog='vouch',
        description='Vouch Protocol CLI - Identity & Reputation for AI Agents'
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # init command
    p_init = subparsers.add_parser('init', help='Generate a new agent identity')
    p_init.add_argument('--domain', help='Domain for the DID (e.g., example.com)')
    p_init.add_argument('--env', action='store_true', help='Output as environment variables')
    
    # sign command
    p_sign = subparsers.add_parser('sign', help='Sign a message or payload')
    p_sign.add_argument('message', help='The message to sign')
    p_sign.add_argument('--json', action='store_true', help='Parse message as JSON')
    p_sign.add_argument('--key', help='Private key (JWK JSON)')
    p_sign.add_argument('--did', help='Agent DID')
    p_sign.add_argument('--header', action='store_true', help='Output with Vouch-Token header prefix')
    
    # verify command
    p_verify = subparsers.add_parser('verify', help='Verify a Vouch-Token')
    p_verify.add_argument('token', help='The token to verify')
    p_verify.add_argument('--key', help='Public key (JWK JSON) for signature verification')
    p_verify.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose if hasattr(args, 'verbose') else False)
    
    if args.command == 'init':
        return cmd_init(args)
    elif args.command == 'sign':
        return cmd_sign(args)
    elif args.command == 'verify':
        return cmd_verify(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
