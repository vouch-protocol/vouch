# vouch-langgraph

Sign every LangGraph tool call and graph node with a Vouch Credential, so an
agent's actions carry a verifiable record of who ran them and on whose authority.

LangGraph tools are LangChain tools, so tool-level signing is shared with the
LangChain integration. On top of that, `sign_node` signs each node step, giving
a signed trail across the whole graph.

## Install

```bash
pip install vouch-langgraph
```

## Sign the tools

```python
from langgraph.prebuilt import create_react_agent
from vouch.integrations.langgraph import protect

agent = create_react_agent(llm, tools=protect([search, send_email]))
```

Every tool call is now signed in Python before it runs.

## Sign each node

```python
from vouch.integrations.langgraph import sign_node

@sign_node
def plan(state):
    ...

@sign_node(action="charge_card")
def bill(state):
    ...
```

Each node step issues its own credential. Verify anywhere with
`vouch.Verifier.verify_credential`, or read the latest with
`vouch.autosign.current_credential`.

## Identity

`protect` and `sign_node` use the ambient Vouch identity, or a `signer=` you
pass in. Provision one with `vouch init --yes`, or construct a `Signer`
directly. See the [Vouch Protocol docs](https://vouch-protocol.com).

## License

Apache-2.0. Part of the [Vouch Protocol](https://github.com/vouch-protocol/vouch).
