# vouch-mlflow: your verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-mlflow-test && source /tmp/vouch-mlflow-test/bin/activate
pip install -e packages/vouch-mlflow   # pulls vouch-protocol
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-mlflow/tests -q
```

Expect: 4 passed. They check exports, sign-and-verify of a model file, that a
tampered model fails closed, and that a directory model signs and verifies.

## 3. Real MLflow run (recommended)

```bash
pip install mlflow
```

In a real MLflow run, log a model, call `sign_model` on its local path, set the
returned credential as a run tag, then later `verify_model` on the downloaded
artifact. Confirm a clean model verifies and a modified one fails.

## 4. Build

```bash
pip install build && python -m build packages/vouch-mlflow
unzip -l packages/vouch-mlflow/dist/*.whl   # confirm only vouch_mlflow is packaged
```

## 5. Only after the above

- [ ] Publish to PyPI under your account.
- [ ] No upstream PR is required (MLflow plugin model). Optionally write a short
      MLflow docs/community post showing the pattern.
