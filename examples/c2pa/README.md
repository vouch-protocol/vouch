# C2PA Signing Examples

This directory contains examples for signing images with C2PA manifests using Vouch Protocol.

## Supported Formats

Vouch Protocol supports C2PA signing for the following image formats:

| Format | MIME Type | Extension |
|--------|-----------|-----------|
| JPEG | image/jpeg | .jpg, .jpeg |
| PNG | image/png | .png |
| WebP | image/webp | .webp |
| GIF | image/gif | .gif |
| TIFF | image/tiff | .tiff, .tif |

## Quick Start

### Prerequisites

```bash
# Install c2pa-python
pip install c2pa-python Pillow

# Or install c2patool CLI (requires Rust)
cargo install c2patool
```

### Sign an Image

```bash
python c2pa_signing_example.py photo.jpg \
  --key path/to/private.key \
  --cert path/to/chain.pem \
  --title "My Signed Photo"
```

### Verify a Signed Image

```bash
python c2pa_signing_example.py signed_photo.jpg --verify
```

## Creating Test Certificates

For testing purposes, you can create a certificate chain:

```bash
# 1. Generate Root CA
openssl req -x509 -new -nodes -keyout root.key -out root.pem \
  -days 3650 -subj "/CN=Test Root CA/O=Test"

# 2. Generate Intermediate
openssl req -new -nodes -keyout intermediate.key -out intermediate.csr \
  -subj "/CN=Test Intermediate/O=Test"
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key \
  -CAcreateserial -out intermediate.pem -days 365 \
  -extfile <(echo "basicConstraints=critical,CA:TRUE,pathlen:0")

# 3. Generate Leaf (Signer)
openssl req -new -nodes -keyout leaf.key -out leaf.csr \
  -subj "/CN=Vouch Signer/O=Vouch Protocol"
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key \
  -CAcreateserial -out leaf.pem -days 365 \
  -extfile <(echo -e "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=emailProtection")

# 4. Bundle certificate chain
cat leaf.pem intermediate.pem > chain.pem

# 5. Sign an image
python c2pa_signing_example.py test.jpg --key leaf.key --cert chain.pem
```

## Using with Vouch Protocol's Media Module

```python
from vouch.media.c2pa import MediaSigner, VouchIdentity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Create identity
identity = VouchIdentity(
    did="did:web:example.vouch-protocol.com",
    display_name="Example Signer",
    credential_type="FREE"
)

# Create signer (requires Ed25519 key and certificate)
signer = MediaSigner(
    private_key=your_private_key,
    certificate_chain=your_cert_chain_pem,
    identity=identity
)

# Sign image
result = signer.sign_image("photo.jpg", "photo_signed.jpg")
print(f"Signed: {result.output_path}")
```

## Verification with Adobe

Upload signed images to [contentcredentials.org/verify](https://contentcredentials.org/verify) to verify they are properly formatted.

## Related

- [C2PA Specification](https://c2pa.org/specifications/)
- [Vouch Protocol Documentation](https://github.com/vouch-protocol/vouch)
