# Vouch Bridge Daemon

A local daemon that securely holds Ed25519 keys and signs data on behalf of Vouch Protocol adapters (Browser Extension, CLI, VSCode, etc.).

## Security

- **Keys stored in system keyring** (Windows Credential Locker, macOS Keychain, Linux Secret Service)
- **Listens only on localhost** (127.0.0.1:7823)
- **Human-in-the-Loop consent** - Requires user approval before signing

### Consent UI

When a request hits `/sign`, the daemon shows a system popup asking for approval:

```
┌────────────────────────────────────────┐
│  🔐 SIGNATURE REQUEST                  │
│                                        │
│  Origin: https://twitter.com           │
│                                        │
│  Content Preview:                      │
│  ─────────────────────────────         │
│  Hello, this is my signed message...   │
│  ─────────────────────────────         │
│                                        │
│  Hash: a1b2c3d4...                     │
│                                        │
│  [  Deny  ]          [ Approve ]       │
└────────────────────────────────────────┘
```

#### Consent Modes

| Mode | Behavior |
|------|----------|
| `always` | Always show popup (default, most secure) |
| `prompt` | Show popup for untrusted origins only |
| `never` | No popups (DANGEROUS - testing only) |

```bash
# Set consent mode
VOUCH_CONSENT_MODE=always vouch-bridge
```

## Installation


```bash
# From vouch-bridge directory
pip install -e .

# Or install dependencies directly
pip install fastapi uvicorn keyring cryptography pydantic base58
```

## Usage

```bash
# Start the daemon
vouch-bridge

# Or run directly
python bridge.py

# Or with uvicorn
uvicorn bridge:app --host 127.0.0.1 --port 7823
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Health check |
| GET | `/keys/public` | Get public key (Base64 + DID) |
| POST | `/keys/generate` | Generate new keypair |
| POST | `/sign` | Sign content |

### Examples

```bash
# Check status
curl http://127.0.0.1:7823/status

# Generate keys (first time only)
curl -X POST http://127.0.0.1:7823/keys/generate

# Get public key
curl http://127.0.0.1:7823/keys/public

# Sign content
curl -X POST http://127.0.0.1:7823/sign \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, World!", "origin": "curl-test"}'
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Browser         │     │ CLI             │     │ VSCode          │
│ Extension       │     │                 │     │ Extension       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Vouch Bridge Daemon  │
                    │    (localhost:7823)     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    System Keyring       │
                    │    (Encrypted Keys)     │
                    └─────────────────────────┘
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VOUCH_BRIDGE_HOST` | `127.0.0.1` | Host to bind to |
| `VOUCH_BRIDGE_PORT` | `7823` | Port to listen on |

## Running as a Service

### macOS (launchd)

```bash
# Create plist file
cat > ~/Library/LaunchAgents/com.vouch.bridge.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vouch.bridge</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vouch-bridge</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load the service
launchctl load ~/Library/LaunchAgents/com.vouch.bridge.plist
```

### Linux (systemd)

```bash
# Create service file
sudo cat > /etc/systemd/user/vouch-bridge.service << EOF
[Unit]
Description=Vouch Bridge Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/vouch-bridge
Restart=always

[Install]
WantedBy=default.target
EOF

# Enable and start
systemctl --user enable vouch-bridge
systemctl --user start vouch-bridge
```

### Windows (Task Scheduler)

Use Task Scheduler to run `vouch-bridge.exe` at login.

## License

MIT
