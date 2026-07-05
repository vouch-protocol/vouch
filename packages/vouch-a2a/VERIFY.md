# vouch-a2a: your verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-a2a-test && source /tmp/vouch-a2a-test/bin/activate
pip install -e packages/vouch-a2a   # pulls vouch-protocol
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-a2a/tests -q
```

Expect: 4 passed. They check exports, sign-and-verify of an Agent Card, that an
unsigned card fails closed, and that a delegation chain on a card verifies.

## 3. Real A2A card (recommended)

Take an actual Agent Card from your A2A deployment, sign it with
`sign_agent_card`, serve it, and confirm a peer using `verify_agent_card`
accepts it and rejects a tampered or unsigned one.

## 4. Build

```bash
pip install build && python -m build packages/vouch-a2a
unzip -l packages/vouch-a2a/dist/*.whl   # confirm only vouch_a2a is packaged
```

## 5. Only after the above

- [ ] Publish to PyPI under your account.
- [ ] Open a proposal/issue on `a2aproject/A2A` for an optional signed-identity
      extension on Agent Cards, citing this package as the reference.
- [ ] List the agent in the A2A directory once signed.

Design note: v0.1 binds the credential to the card's `url` (stable agent
identity), not a hash of the full card, so routine capability/skill updates do
not invalidate it. If you want tamper-evidence of the whole card, we can add an
optional content-digest binding in a later version.
