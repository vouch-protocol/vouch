# vouch-openai

Sign the tool (function) calls an OpenAI agent makes with Vouch Protocol Credentials, so every action an OpenAI-driven agent takes carries a verifiable identity and a non-repudiable record.

It works with the OpenAI Python SDK function calling (Chat Completions and the Responses API) and with the OpenAI Agents SDK, because all of them dispatch to Python tool callables and expose a tool call as a name plus JSON arguments.

## Install

```bash
pip install vouch-openai
```

## Configure an identity

```bash
export VOUCH_DID='did:web:your-agent.example.com'
export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519",...}'
```

Generate one with `vouch init --domain your-agent.example.com --env`, or pass a `Signer` explicitly.

## Sign the model's requested tool call

```python
from openai import OpenAI
from vouch.integrations.openai import sign_tool_call

client = OpenAI()
response = client.chat.completions.create(model="gpt-4o", messages=messages, tools=tools)

for call in response.choices[0].message.tool_calls:
    credential = sign_tool_call(call)   # binds the action and its arguments
    result = dispatch(call)             # run your tool
```

## Sign the tool callables

```python
from vouch.integrations.openai import signed_tool, protect

@signed_tool
def get_weather(city: str) -> str:
    ...

tools = protect([get_weather, send_email])   # every invocation is signed
```

## Verify

```python
from vouch.integrations.openai import verify_tool_call

ok, passport = verify_tool_call(credential)
```

A tool runs whether or not an identity is resolved; when none is configured, signing is skipped and the call proceeds unsigned.

## License

Apache-2.0. Part of [Vouch Protocol](https://vouch-protocol.com).
