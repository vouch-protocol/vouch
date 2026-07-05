# vouch-langchain: your verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-lc-test && source /tmp/vouch-lc-test/bin/activate
pip install -e packages/vouch-langchain   # pulls vouch-protocol[langchain]
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-langchain/tests -q
```

Expect: 2 passed. They check the exports and that the tool issues an
`eddsa-jcs-2022` credential that verifies.

## 3. Real LangChain agent (recommended)

Add `VouchSignerTool()` to an actual LangChain agent's tool list, run a prompt
that triggers an authenticated call, and confirm the agent calls the tool and
forwards the credential.

## 4. Build

```bash
pip install build && python -m build packages/vouch-langchain
unzip -l packages/vouch-langchain/dist/*.whl   # confirm only vouch_langchain is packaged
```

## 5. Only after the above

- [ ] Publish to PyPI under your account.
- [ ] Add the listing to LangChain's integration docs/registry. If their registry
      expects the `langchain-vouch` name, publish the thin alias shim (see the
      plan doc, Part 8) that depends on and re-exports `vouch-langchain`.
