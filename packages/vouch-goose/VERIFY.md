# vouch-goose: verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-goose-test && source /tmp/vouch-goose-test/bin/activate
pip install -e packages/vouch-goose   # pulls vouch-protocol and vouch-mcp
```

## 2. Smoke tests

```bash
pip install pytest pyyaml
pytest packages/vouch-goose/tests -q
```

Expect: 5 passed. They check exports, the extension config shape, that install
creates the file and registers the extension, that it preserves existing config,
and that `--keep-existing` leaves an existing entry intact.

## 3. Real Goose (recommended)

```bash
vouch-goose
```

Confirm a `vouch` extension appears under `extensions:` in
`~/.config/goose/config.yaml`, then start Goose and check the Vouch tools are
listed and callable.

## 4. Build

```bash
python -m build packages/vouch-goose
```
