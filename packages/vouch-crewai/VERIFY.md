# vouch-crewai: your verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-crew-test && source /tmp/vouch-crew-test/bin/activate
pip install -e packages/vouch-crewai   # pulls vouch-protocol[crewai]
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-crewai/tests -q
```

Expect: 2 passed. They check the exports and that the signing path issues an
`eddsa-jcs-2022` credential that verifies.

## 3. Real crew with delegation (recommended)

Run `examples/integrations_delegation.py` from the main repo, then give
`sign_request` to a two-agent crew and confirm a supervisor credential and a
narrowed worker credential both verify.

## 4. Build

```bash
pip install build && python -m build packages/vouch-crewai
unzip -l packages/vouch-crewai/dist/*.whl   # confirm only vouch_crewai is packaged
```

## 5. Only after the above

- [ ] Publish to PyPI under your account.
- [ ] Add the listing to the CrewAI tools docs or contribute to crewai-tools.
