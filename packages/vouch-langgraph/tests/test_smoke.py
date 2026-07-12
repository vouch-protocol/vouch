"""Smoke tests for the vouch-langgraph package."""

from vouch import Signer, generate_identity
from vouch.autosign import current_credential


def _signer():
    kp = generate_identity()
    return Signer(private_key=kp.private_key_jwk, did="did:web:agent.example")


def test_package_exports():
    import vouch_langgraph

    assert vouch_langgraph.protect is not None
    assert vouch_langgraph.sign_node is not None


def test_protect_signs_plain_callable():
    from vouch_langgraph import protect

    signer = _signer()

    def search(q: str) -> str:
        return f"results for {q}"

    wrapped = protect([search], signer=signer)[0]
    out = wrapped("hello")

    assert out == "results for hello"
    cred = current_credential()
    assert cred is not None
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"


def test_sign_node_signs_each_step():
    from vouch_langgraph import sign_node

    signer = _signer()

    @sign_node(action="plan", signer=signer)
    def plan(state: dict) -> dict:
        return {**state, "planned": True}

    result = plan({"x": 1})

    assert result["planned"] is True
    cred = current_credential()
    assert cred is not None
    assert cred["proof"]["cryptosuite"] == "eddsa-jcs-2022"


def test_sign_node_bare_decorator_runs():
    from vouch_langgraph import sign_node

    @sign_node
    def step(state: dict) -> dict:
        return {**state, "seen": True}

    # No signer resolved here, so the step runs unsigned but still returns.
    assert step({"x": 1})["seen"] is True
