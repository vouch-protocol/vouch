# Python SDK Examples

This directory contains examples demonstrating all features of the Vouch Python SDK.

## Quick Start

```bash
# Install the SDK
pip install vouch-sdk

# Ensure the daemon is running
vouch-bridge
```

## Examples

### Basic Usage
- `basic_connect.py` - Connect to daemon and check status
- `basic_sign_text.py` - Sign text content
- `basic_verify.py` - Verify signed content

### File Operations
- `sign_file.py` - Sign a file (any type)
- `sign_image.py` - Sign an image with C2PA
- `sign_video.py` - Sign a video file
- `verify_media.py` - Verify C2PA manifest in media

### Async Operations
- `async_client.py` - Using AsyncVouchClient
- `async_batch_sign.py` - Sign multiple items concurrently

### CLI Usage
- `cli_examples.sh` - Shell script showing CLI commands

### Error Handling
- `error_handling.py` - Graceful error handling patterns

### Integration Examples
- `fastapi_integration.py` - Use with FastAPI
- `django_integration.py` - Use with Django
- `langchain_integration.py` - Use with LangChain agents
