# vouch-langgraph: verification checklist (do this before publishing)

Nothing here has been published. Run these yourself, confirm each, then decide.

## 1. Clean install

```bash
python -m venv /tmp/vouch-langgraph-test && source /tmp/vouch-langgraph-test/bin/activate
pip install -e packages/vouch-langgraph   # pulls vouch-protocol
```

## 2. Smoke tests

```bash
pip install pytest
pytest packages/vouch-langgraph/tests -q
```

Expect: 4 passed. They check exports, that a protected tool call is signed,
that a signed node issues a credential, and that a bare node still runs when no
identity is resolved.

## 3. Real graph (recommended)

Wrap the tools in an actual LangGraph agent with `protect([...])`, decorate a
node with `@sign_node`, run the graph, and confirm `current_credential()`
returns a credential that `Verifier.verify_credential` accepts.

## 4. Build

```bash
python -m build packages/vouch-langgraph
```
