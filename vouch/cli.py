import argparse
import sys
import json
import os
from vouch.signer import Signer
from vouch.verifier import Verifier

try:
    from nacl.signing import SigningKey
    from nacl.encoding import HexEncoder
except ImportError:
    SigningKey = None

def cmd_init(args):
    if not SigningKey:
        print("Error: pip install pynacl required")
        return
    k = SigningKey.generate()
    priv = k.encode(encoder=HexEncoder).decode('utf-8')
    pub = k.verify_key.encode(encoder=HexEncoder).decode('utf-8')
    did = f"did:web:{args.domain}" if args.domain else "did:web:example.com"
    print(f"VOUCH_DID={did}\nVOUCH_PRIVATE_KEY={priv}\n# Public: {pub}")

def cmd_sign(args):
    priv = args.key or os.environ.get('VOUCH_PRIVATE_KEY')
    did = args.did or os.environ.get('VOUCH_DID')
    if not priv or not did:
        print("Error: Missing credentials")
        return
    signer = Signer(private_key=priv, did=did)
    payload = json.loads(args.message) if args.json else args.message
    print(signer.sign(payload))

def cmd_verify(args):
    valid, passport = Verifier.verify(args.token)
    print(f"VALID: {passport.sub}" if valid else "INVALID")

def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest='command')
    
    p_init = subs.add_parser('init')
    p_init.add_argument('--domain')
    
    p_sign = subs.add_parser('sign')
    p_sign.add_argument('message')
    p_sign.add_argument('--json', action='store_true')
    p_sign.add_argument('--key')
    p_sign.add_argument('--did')
    
    p_ver = subs.add_parser('verify')
    p_ver.add_argument('token')
    
    args = parser.parse_args()
    if args.command == 'init': cmd_init(args)
    elif args.command == 'sign': cmd_sign(args)
    elif args.command == 'verify': cmd_verify(args)
    else: parser.print_help()

if __name__ == '__main__': main()
