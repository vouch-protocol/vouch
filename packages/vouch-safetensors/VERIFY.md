# vouch-safetensors: your verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-st-test && source /tmp/vouch-st-test/bin/activate
pip install -e packages/vouch-safetensors   # pulls vouch-protocol
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-safetensors/tests -q
```

Expect: 4 passed. They build a minimal safetensors file, sign and verify it,
confirm tampered weights fail closed, and confirm an unsigned file fails closed.

## 3. Real model + Hugging Face load (recommended)

Sign a real `.safetensors` file, then load it with the `safetensors` library or
`transformers` and confirm it still loads normally (the extra `__metadata__`
key is ignored by standard loaders). Then `verify_safetensors` it.

```bash
pip install safetensors
```

## 4. Build

```bash
pip install build && python -m build packages/vouch-safetensors
unzip -l packages/vouch-safetensors/dist/*.whl   # confirm only vouch_safetensors is packaged
```

## 5. Only after the above

- [ ] Publish to PyPI under your account.
- [ ] Engage the OpenSSF AI/ML Working Group to position the Vouch credential as
      an identity payload alongside OMS, rather than a competing signature.
