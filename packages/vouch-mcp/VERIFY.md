# vouch-mcp: your verification checklist (do this before publishing)

Nothing here has been published. Run these steps yourself, confirm each, then
you decide whether to publish to PyPI and submit to `modelcontextprotocol/servers`.

## 1. Clean install in a throwaway venv

```bash
python -m venv /tmp/vouch-mcp-test && source /tmp/vouch-mcp-test/bin/activate
pip install -e packages/vouch-mcp        # pulls vouch-protocol[mcp]
```

Expect: install succeeds, `vouch-mcp` is on PATH (`which vouch-mcp`).

## 2. Run the smoke tests

```bash
pip install pytest
pytest packages/vouch-mcp/tests -q
```

Expect: 3 passed. They check the package exports, that the MCP server has
`sign` / `create_session` / `get_identity` registered, and that the
issued credential is `eddsa-jcs-2022` and verifies.

## 3. Build the distribution

```bash
pip install build
python -m build packages/vouch-mcp
```

Expect: a wheel and sdist in `packages/vouch-mcp/dist/`. Inspect the wheel
contents (`unzip -l dist/*.whl`) and confirm only `vouch_mcp` is included.

## 4. End-to-end with a real MCP client (optional but recommended)

```bash
python -c "from vouch import generate_identity; print(generate_identity().private_key_jwk)"
```

Set that as `VOUCH_PRIVATE_KEY` and a DID as `VOUCH_DID`, then register the
`vouch-mcp` command as an stdio server in Claude Desktop or Cursor. Confirm the
tools appear and that `sign` returns a credential.

## 5. Only after all of the above

- [ ] Publish to PyPI under your account.
- [ ] Open the PR to `modelcontextprotocol/servers` adding the `vouch` entry.
- [ ] List it in the official MCP server registry.

Naming note: the main `vouch-protocol` package also installs a `vouch-mcp`
console script pointing at the same entry point. If you install both into one
environment the script names collide. Recommended: this standalone package is
the canonical distribution of the server; depend on it directly.
