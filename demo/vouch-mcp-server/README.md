# Vouch Protocol MCP Server

This demo exposes Vouch Protocol capabilities as an **MCP (Model Context Protocol)** server.
This allows AI agents (like Claude Desktop) to natively sign and verify media files on your computer.

## 🛠️ Usage with Claude Desktop

1.  **Install Dependencies**:
    ```bash
    pip install mcp[cli] c2pa-python
    pip install -e ../../  # Install Vouch Protocol
    ```

2.  **Configure Claude Desktop**:
    Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (MacOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) / `~/.config/Claude/claude_desktop_config.json` (Linux).

    Add this entry:

    ```json
    {
      "mcpServers": {
        "vouch": {
          "command": "python3",
          "args": ["/absolute/path/to/vouch-protocol/demo/vouch-mcp-server/server.py"]
        }
      }
    }
    ```

3.  **Restart Claude**:
    You will now see 🛠️ icons for `sign_image` and `verify_image`.

## 🤖 Example Prompts for Claude

- "Please generate an identity for me."
- "Sign this prompt to prove I wrote it: 'Hello World'"
- "Verify this text token: eyJ..."

### 📸 Image Signing (Experimental)
Image signing is available via `sign_image` but requires a valid X.509 certificate chain. Self-signed certificates may be rejected by some C2PA validators.

- "Authentically sign this photo: /path/to/sunset.jpg"
- "Verify if this image is real: /path/to/news.jpg"

## 🧠 Scribe Context
This project uses **Scribe**.
- Context: `.scribe/handoff.md`
