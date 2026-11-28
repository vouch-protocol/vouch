"""
Tests for the `vouch onboard` wizard.

The wizard writes starter files: a DID document, an allow-list, a tool-call
wrapper and a verifier. These tests run the generated Python files for real: a
credential signed by the wizard's identity has to pass the generated verifier,
and anything forged, altered, or outside the allow-list has to be turned away.
"""

import base64
import copy
import json
import types
from pathlib import Path

import pytest

import vouch
from vouch import onboard
from vouch.keys import KeyManager, generate_identity

DOMAIN = "agent.example.com"
DID = f"did:web:{DOMAIN}"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A temp keystore, a temp wizard state file, and an output directory."""
    keystore = tmp_path / "keys"
    keystore.mkdir()
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=str(keystore): orig_init(self, str(keystore))
    )
    monkeypatch.setattr(onboard, "STATE_PATH", tmp_path / "state" / "onboarding.json")
    out = tmp_path / "out"
    out.mkdir()
    return types.SimpleNamespace(keystore=keystore, out=out, tmp=tmp_path)


def run(workspace, lang="python", domain=DOMAIN, out_dir=None, **kwargs):
    answers = {"domain": domain, "toolwire_lang": lang, "verifier_lang": lang}
    return onboard.run_wizard(
        reset=True,
        interactive=False,
        out_dir=str(out_dir or workspace.out),
        preset_answers=answers,
        **kwargs,
    )


def load_module(path, name):
    """Execute a generated Python starter file and return its namespace."""
    namespace = {"__name__": name}
    exec(compile(path.read_text(), str(path), "exec"), namespace)
    return namespace


def stored_keys(did=DID):
    return KeyManager().load_identity(did)


def intent(action="http.post"):
    return {
        "action": action,
        "target": "partner-api",
        "resource": "https://api.partner.example/orders",
    }


def as_header(credential):
    return {"Vouch-Token": json.dumps(credential, separators=(",", ":"))}


# ---------------------------------------------------------------------------
# What gets written
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lang,ext", [("python", "py"), ("typescript", "ts"), ("go", "go")])
def test_wizard_writes_every_starter_file(workspace, lang, ext):
    assert run(workspace, lang=lang) == 0

    names = {p.name for p in workspace.out.iterdir()}
    assert names == {
        "did.json",
        "vouch-allowlist.json",
        f"vouch-toolwire.{ext}",
        f"vouch-verifier.{ext}",
        "vouch-heartbeat.yaml",
    }
    for name in (f"vouch-toolwire.{ext}", f"vouch-verifier.{ext}"):
        text = (workspace.out / name).read_text()
        assert "@@" not in text, f"{name} has an unfilled placeholder"
        assert DID in text


@pytest.mark.parametrize("artifact", ["vouch-toolwire.py", "vouch-verifier.py"])
def test_website_preview_matches_what_the_wizard_writes(workspace, monkeypatch, artifact):
    """The /onboard page previews these files, so it has to show the real thing."""
    page = Path(__file__).resolve().parent.parent / "website/src/app/onboard/onboard-data.ts"
    if not page.exists():
        pytest.skip("website sources are not part of this checkout")
    source = page.read_text()
    start = source.index("preview: `", source.index(f"artifact: '{artifact}'")) + len("preview: `")
    preview = source[start : source.index("`,\n    eta:", start)].replace("\\`", "`")

    monkeypatch.chdir(workspace.out)
    assert run(workspace, domain="agent.acme.example", out_dir=".") == 0
    written = (workspace.out / artifact).read_text()
    public_x = json.loads(stored_keys("did:web:agent.acme.example").public_key_jwk)["x"]
    # The page shows the code without the module docstring, and a stand-in key.
    body = written.split('"""\n', 1)[1].replace(public_x, "<base64url public key>")

    assert preview.strip() == body.strip()


def test_every_template_placeholder_is_known():
    state = onboard.OnboardState(did=DID, public_key_jwk=generate_identity(DOMAIN).public_key_jwk)
    values = onboard._starter_values(state)
    for templates in (onboard._TOOLWIRE_SNIPPETS, onboard._VERIFIER_SNIPPETS):
        for lang, template in templates.items():
            assert "@@" not in onboard._render(template, values), lang

    with pytest.raises(ValueError):
        onboard._render("x = @@NOT_A_VALUE@@", values)


@pytest.mark.parametrize("lang,ext", [("python", "py"), ("typescript", "ts"), ("go", "go")])
def test_starter_files_match_the_sidecar_and_pin_the_issuer_key(workspace, lang, ext):
    assert run(workspace, lang=lang) == 0
    toolwire = (workspace.out / f"vouch-toolwire.{ext}").read_text()
    verifier = (workspace.out / f"vouch-verifier.{ext}").read_text()

    # The wrapper talks to the sidecar's own address and request shape.
    assert "http://127.0.0.1:8877/sign" in toolwire
    assert "intent" in toolwire
    assert "Vouch-Token" in toolwire and "Vouch-Token" in verifier

    # The verifier checks signatures against this identity's public key.
    public = json.loads(stored_keys().public_key_jwk)
    raw_public = base64.urlsafe_b64decode(public["x"] + "=" * (-len(public["x"]) % 4))
    pinned = vouch.multikey.encode_ed25519_public(raw_public) if lang == "go" else public["x"]
    assert pinned in verifier

    # No private key material in anything the wizard writes to the project.
    private_d = json.loads(stored_keys().private_key_jwk)["d"]
    for path in workspace.out.iterdir():
        assert private_d not in path.read_text(), f"{path.name} holds the private key"


def test_typescript_and_go_verifiers_call_the_real_sdk(workspace):
    assert run(workspace, lang="typescript") == 0
    ts = (workspace.out / "vouch-verifier.ts").read_text()
    assert 'import { verify } from "@vouch-protocol-official/sdk"' in ts
    assert "await verify(token, ISSUER_PUBLIC_KEY)" in ts
    assert "throw new Error" not in ts

    assert run(workspace, lang="go") == 0
    go = (workspace.out / "vouch-verifier.go").read_text()
    assert '"github.com/vouch-protocol/vouch/go-sidecar/signer"' in go
    assert "signer.Verify(credential, issuerKey, 30)" in go
    assert "passport.Issuer != IssuerDID" in go


def test_did_document_carries_the_public_key_only(workspace):
    assert run(workspace) == 0
    doc = json.loads((workspace.out / "did.json").read_text())
    assert doc["id"] == DID
    jwk = doc["verificationMethod"][0]["publicKeyJwk"]
    assert jwk == {k: json.loads(stored_keys().public_key_jwk)[k] for k in ("kty", "crv", "x")}
    assert '"d"' not in json.dumps(doc)


def test_dry_run_writes_nothing(workspace):
    assert run(workspace, dry_run=True) == 0
    assert list(workspace.out.iterdir()) == []
    assert list(workspace.keystore.iterdir()) == []


# ---------------------------------------------------------------------------
# The generated Python verifier, run for real
# ---------------------------------------------------------------------------


@pytest.fixture
def api(workspace):
    """The generated FastAPI app behind a test client."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    assert run(workspace) == 0
    module = load_module(workspace.out / "vouch-verifier.py", "vouch_verifier")
    return TestClient(module["app"])


def test_verifier_accepts_a_credential_from_the_wizard_identity(workspace, api):
    credential = vouch.sign(stored_keys(), intent("http.post"))

    response = api.post("/example", headers=as_header(credential))

    assert response.status_code == 200
    assert response.json() == {"agent": DID, "action": "http.post"}


def test_verifier_rejects_a_request_with_no_credential(workspace, api):
    assert api.post("/example").status_code == 401


def test_verifier_rejects_an_altered_credential(workspace, api):
    credential = vouch.sign(stored_keys(), intent("read.file"))
    altered = copy.deepcopy(credential)
    altered["credentialSubject"]["intent"]["action"] = "http.post"

    assert api.post("/example", headers=as_header(altered)).status_code == 401


def test_verifier_rejects_a_credential_with_no_proof(workspace, api):
    credential = vouch.sign(stored_keys(), intent("http.post"))
    del credential["proof"]

    assert api.post("/example", headers=as_header(credential)).status_code == 401


def test_verifier_rejects_another_key_claiming_the_same_issuer(workspace, api):
    impostor = generate_identity(DOMAIN)  # same DID, a key the verifier never pinned
    credential = vouch.sign(impostor, intent("http.post"))

    assert api.post("/example", headers=as_header(credential)).status_code == 401


def test_verifier_rejects_a_different_issuer(workspace, api):
    stranger = generate_identity("stranger.example.com")
    credential = vouch.sign(stranger, intent("http.post"))

    assert api.post("/example", headers=as_header(credential)).status_code == 401


def test_verifier_rejects_an_expired_credential(workspace, api):
    from datetime import datetime, timedelta, timezone

    signer = vouch.Signer(private_key=stored_keys().private_key_jwk, did=DID)
    credential = signer.sign(
        intent=intent("http.post"),
        valid_seconds=60,
        valid_from=datetime.now(timezone.utc) - timedelta(hours=2),
    )

    assert api.post("/example", headers=as_header(credential)).status_code == 401


def test_verifier_rejects_an_action_off_the_allowlist(workspace, api):
    credential = vouch.sign(stored_keys(), intent("ledger.transfer"))

    response = api.post("/example", headers=as_header(credential))

    assert response.status_code == 403


@pytest.mark.parametrize("garbage", ["not json", "{}", "[]", '{"issuer": "did:web:x"}'])
def test_verifier_rejects_garbage(workspace, api, garbage):
    assert api.post("/example", headers={"Vouch-Token": garbage}).status_code == 401


# ---------------------------------------------------------------------------
# The generated Python tool wrapper, run against a stand-in sidecar
# ---------------------------------------------------------------------------


class FakeSidecar:
    """Answers the wrapper's POST the way the sidecar does, and records it."""

    def __init__(self, keys):
        self.signer = vouch.Signer(private_key=keys.private_key_jwk, did=keys.did)
        self.calls = []

    def post(self, url, json=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "json": json})
        credential = self.signer.sign(intent=json["intent"])
        return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: credential)


def test_tool_wrapper_and_verifier_work_together(workspace, api, monkeypatch):
    import httpx

    sidecar = FakeSidecar(stored_keys())
    monkeypatch.setattr(httpx, "post", sidecar.post)
    wrapper = load_module(workspace.out / "vouch-toolwire.py", "vouch_toolwire")

    @wrapper["vouch_tool"](
        "http.post", target="partner-api", resource="https://api.partner.example/orders"
    )
    def send_to_partner(body, _vouch_headers=None):
        return api.post("/example", json=body, headers=_vouch_headers)

    response = send_to_partner({"order": 1})

    assert response.status_code == 200
    assert response.json()["action"] == "http.post"
    assert sidecar.calls == [
        {
            "url": "http://127.0.0.1:8877/sign",
            "json": {
                "intent": {
                    "action": "http.post",
                    "target": "partner-api",
                    "resource": "https://api.partner.example/orders",
                }
            },
        }
    ]


def test_tool_wrapper_passes_the_callers_validity(workspace, monkeypatch):
    import httpx

    assert run(workspace) == 0
    fake = FakeSidecar(stored_keys())
    monkeypatch.setattr(httpx, "post", fake.post)
    wrapper = load_module(workspace.out / "vouch-toolwire.py", "vouch_toolwire")

    wrapper["vouch_headers"]("http.post", "partner-api", "https://api.partner.example/orders")
    wrapper["vouch_headers"](
        "http.post", "partner-api", "https://api.partner.example/orders", valid_seconds=120
    )

    assert "validSeconds" not in fake.calls[0]["json"]
    assert fake.calls[1]["json"]["validSeconds"] == 120


def test_summary_starts_the_sidecar_without_a_key_flag(workspace, capsys):
    assert run(workspace) == 0
    out = capsys.readouterr().out
    assert f"vouch sidecar --did {DID} --allowlist" in out
    assert "--key" not in out


def test_tool_wrapper_refuses_a_sidecar_signing_as_someone_else(workspace, monkeypatch):
    import httpx

    assert run(workspace) == 0
    monkeypatch.setattr(httpx, "post", FakeSidecar(generate_identity("other.example.com")).post)
    wrapper = load_module(workspace.out / "vouch-toolwire.py", "vouch_toolwire")

    with pytest.raises(RuntimeError):
        wrapper["vouch_headers"]("http.post", "partner-api", "https://api.partner.example/orders")


def test_tool_wrapper_header_is_ascii_for_non_ascii_intents(workspace, monkeypatch):
    import httpx

    assert run(workspace) == 0
    monkeypatch.setattr(httpx, "post", FakeSidecar(stored_keys()).post)
    wrapper = load_module(workspace.out / "vouch-toolwire.py", "vouch_toolwire")

    headers = wrapper["vouch_headers"]("http.post", "café ☕", "https://api.partner.example/orders")

    headers["Vouch-Token"].encode("ascii")
    ok, passport = vouch.verify(headers["Vouch-Token"], stored_keys().public_key_jwk)
    assert ok and passport.target == "café ☕"


# ---------------------------------------------------------------------------
# Identity handling
# ---------------------------------------------------------------------------


def test_rerunning_keeps_the_existing_identity(workspace):
    assert run(workspace) == 0
    first = stored_keys().private_key_jwk

    assert run(workspace) == 0

    assert stored_keys().private_key_jwk == first


def test_an_identity_from_vouch_init_is_not_replaced(workspace):
    existing = generate_identity(DOMAIN)
    KeyManager().save_identity(existing, password="correct horse battery staple")

    assert run(workspace) == 0

    kept = KeyManager().load_identity(DID, "correct horse battery staple")
    assert kept.private_key_jwk == existing.private_key_jwk
    verifier = (workspace.out / "vouch-verifier.py").read_text()
    assert json.loads(existing.public_key_jwk)["x"] in verifier


def test_resume_from_a_state_file_without_a_stored_public_key(workspace):
    """A run interrupted by an earlier release picks the key up from the keystore."""
    keys = generate_identity(DOMAIN)
    KeyManager().save_identity(keys)
    state = onboard.OnboardState(out_dir=str(workspace.out), domain=DOMAIN, did=DID)
    for slug in ("identity", "tier", "allowlist"):
        state.steps[slug] = onboard.StepRecord(status="done")
    state.tier = "standard"
    state.allowlist_path = str(workspace.out / "vouch-allowlist.json")
    onboard.save_state(state)

    rc = onboard.run_wizard(resume=True, interactive=False, out_dir=str(workspace.out))

    assert rc == 0
    assert json.loads(keys.public_key_jwk)["x"] in (workspace.out / "vouch-verifier.py").read_text()


# ---------------------------------------------------------------------------
# Hostile and awkward input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        'x" + __import__("os").system("id") + "',
        "agent.example.com\nimport os",
        "https://agent.example.com",
        "agent.example.com/path",
        "agent example.com",
        "agent..example.com",
        "-agent.example.com",
        "agent.example.com:8080",
        "",
        "a" * 300 + ".com",
    ],
)
def test_wizard_refuses_values_that_are_not_domain_names(workspace, domain, capsys):
    args = types.SimpleNamespace(
        quick=False, domain=domain or " ", non_interactive=True, out_dir=str(workspace.out)
    )

    assert onboard.cmd_onboard(args) == 2
    assert "Error:" in capsys.readouterr().err
    assert list(workspace.out.iterdir()) == []
    assert list(workspace.keystore.iterdir()) == []


@pytest.mark.parametrize("domain", ["localhost", "Agent.Example.COM", "localhost%3A8080", "a.b"])
def test_wizard_accepts_plain_hosts(workspace, domain):
    assert run(workspace, domain=domain) == 0
    doc = json.loads((workspace.out / "did.json").read_text())
    assert doc["id"] == f"did:web:{domain.lower()}"


def test_generated_python_survives_an_awkward_output_path(workspace):
    pytest.importorskip("fastapi")
    awkward = workspace.tmp / "we\"ird 'dir' {x} @@DID@@"
    awkward.mkdir()

    assert run(workspace, out_dir=awkward) == 0

    module = load_module(awkward / "vouch-verifier.py", "vouch_verifier_awkward")
    assert module["ISSUER_DID"] == DID
    assert "http.post" in module["ALLOWED_ACTIONS"]
    load_module(awkward / "vouch-toolwire.py", "vouch_toolwire_awkward")
