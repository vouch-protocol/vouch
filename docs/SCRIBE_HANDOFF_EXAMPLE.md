
# SESSION HANDOFF

TIME: 2026-01-25 08:47:31

## INSTRUCTIONS
1. Review the changes below.
2. Update `DEVELOPER_CONTEXT.md` if architectural or significant logical changes occurred.
3. Await further instructions.

## CHANGES (Example)
```diff
commit c34a9f62f910c95e4e83f0c2578d2df2bf122502
Author: Ramprasad Gaddam <groups.rampy1@gmail.com>
Date:   Sat Jan 24 18:20:33 2026 +0000

    feat: MCP server text signing and PAD-015 update
    
    Signed-off-by: Vouch Protocol <Identity-Sidecar>
    Vouch-DID: did:vouch:be434c6279c0
---
 demo/vouch-mcp-server/README.md          |  47 +++
 demo/vouch-mcp-server/server.py          | 173 ++++++++++
 docs/disclosures/index.html              |   9 +
 3 files changed, 229 insertions(+)

diff --git a/demo/vouch-mcp-server/server.py b/demo/vouch-mcp-server/server.py
new file mode 100644
index 0000000..345df0d
--- /dev/null
+++ b/demo/vouch-mcp-server/server.py
@@ -167,6 +167,13 @@ mcp = FastMCP("Vouch Protocol")
 @mcp.tool()
 def create_identity(name: str) -> str:
     """Create a new Vouch Identity (DID + Key) for signing media."""
+    # Generate random DID for demo
+    did = f"did:vouch:{name.lower().replace(' ', '')}"
+    return json.dumps({
+        "did": did,
+        "note": "Identity created successfully"
+    })
+
+@mcp.tool()
+def sign_text(text: str, private_key_jwk: str, did: str) -> str:
+    """
+    Sign a text message or prompt using Vouch Identity.
+    Returns a verifiable JWS token.
+    """
+    try:
+        signer = Signer(private_key=private_key_jwk, did=did)
+        token = signer.sign({"content": text})
+        return token
+    except Exception as e:
+        return f"Error signing text: {str(e)}"
```
