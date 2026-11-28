"""
Tests for the Python signing sidecar (`vouch sidecar`).

The sidecar holds the agent's key and signs what the agent is about to do. These
tests drive it the way a caller would, check that what it signs really verifies,
and check that everything it should refuse is refused.
"""

import argparse
import copy
import io
import json
import threading
import types
import urllib.error
import urllib.request

import pytest

import vouch
from vouch import cli, sidecar
from vouch.keys import KeyManager, generate_identity
from vouch.sidecar import Sidecar, SidecarConfig, SidecarError
from vouch.verifier import MissingMLDSA44KeyError

DID = "did:web:agent.example.com"
HEADERS = {"Host": "127.0.0.1:8877", "Content-Type": "application/json"}
INTENT = {
    "action": "read.file",
    "target": "report",
    "resource": "https://api.example.com/private/customer-8842",
}


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point KeyManager at a temp directory and clear the sidecar's env settings."""
    keystore = tmp_path / "keys"
    keystore.mkdir()
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=str(keystore): orig_init(self, str(keystore))
    )
    for name in (
        sidecar.SEED_ENV,
        sidecar.PRIVATE_KEY_ENV,
        sidecar.DID_ENV,
        sidecar.PASSPHRASE_ENV,
        sidecar.TOKEN_ENV,
        sidecar.HOST_ENV,
        sidecar.DEFAULT_VALIDITY_ENV,
        sidecar.MAX_VALIDITY_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    return keystore


def make(keys=None, log=None, **config):
    """A sidecar for a fresh identity, plus that identity."""
    keys = keys or generate_identity("agent.example.com")
    signer = vouch.Signer(private_key=keys.private_key_jwk, did=keys.did)
    return Sidecar(signer, SidecarConfig(did=keys.did, **config), log_stream=log), keys


def post(sc, body, path="/sign", headers=None, method="POST"):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return sc.handle(method, path, {**HEADERS, **(headers or {})}, raw)


def get(sc, path, headers=None):
    return sc.handle("GET", path, {**HEADERS, **(headers or {})}, b"")


def window(credential):
    from datetime import datetime

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.strptime(credential["validFrom"], fmt)
    end = datetime.strptime(credential["validUntil"], fmt)
    return int((end - start).total_seconds())


def stored(domain="agent.example.com", password=None):
    keys = generate_identity(domain)
    KeyManager().save_identity(keys, password=password)
    return keys


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def test_sign_returns_a_credential_that_verifies():
    sc, keys = make()

    response = post(sc, {"intent": INTENT})

    assert response.status == 200
    credential = response.json()
    assert credential["issuer"] == DID
    ok, passport = vouch.verify(credential, keys.public_key_jwk)
    assert ok and passport.action == "read.file"

    # The key the sidecar publishes checks the same credential.
    published = get(sc, "/pubkey").json()["publicKeyMultibase"]
    assert vouch.verify(credential, published)[0]

    # Any other key, or any change to the credential, fails.
    assert not vouch.verify(credential, generate_identity("agent.example.com").public_key_jwk)[0]
    altered = copy.deepcopy(credential)
    altered["credentialSubject"]["intent"]["action"] = "ledger.transfer"
    assert not vouch.verify(altered, keys.public_key_jwk)[0]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"issuer": DID, "action": "read.file", "args": {}},
        {"intent": {"action": "a", "target": "t"}},
        {"intent": {"action": "", "target": "t", "resource": "r"}},
        {"intent": {"action": ["a"], "target": "t", "resource": "r"}},
        {"intent": "read.file"},
        {"intent": INTENT, "payload": {"x": 1}},
        {"payload": {"action": "read.file"}},
        {"intent": INTENT, "validSeconds": -5},
        {"intent": INTENT, "validSeconds": "soon"},
        {"intent": INTENT, "validSeconds": True},
        {"intent": INTENT, "validSeconds": 1.5},
        {"intent": INTENT, "reputationScore": "high"},
        {"intent": INTENT, "delegationChain": "chain"},
        {"intent": INTENT, "credentialStatus": "revoked"},
        [INTENT],
        b'{"intent":',
        b"\xff\xfe not text",
    ],
)
def test_malformed_requests_are_refused(body):
    sc, _ = make()
    assert post(sc, body).status == 400


def test_sign_needs_post_and_json():
    sc, _ = make()
    assert sc.handle("GET", "/sign", HEADERS, b"").status == 405
    for content_type in ("", "text/plain", "application/x-www-form-urlencoded"):
        response = post(sc, {"intent": INTENT}, headers={"Content-Type": content_type})
        assert response.status == 415, content_type
    ok = post(sc, {"intent": INTENT}, headers={"Content-Type": "application/json; charset=utf-8"})
    assert ok.status == 200


def test_oversized_body_is_refused():
    sc, _ = make()
    huge = {"intent": {**INTENT, "resource": "x" * (sidecar.MAX_BODY_BYTES + 1)}}
    assert post(sc, huge).status == 400


def test_unknown_paths_are_not_found():
    sc, _ = make()
    for path in ("/", "/sign/", "/signature", "/admin", "/sign/hybrid/x"):
        assert get(sc, path).status == 404, path


# ---------------------------------------------------------------------------
# Validity: the caller chooses, the operator sets the default and the ceiling
# ---------------------------------------------------------------------------


def test_caller_chooses_validity_and_gets_the_default_otherwise():
    sc, _ = make(default_valid_seconds=900, max_valid_seconds=7200)

    assert window(post(sc, {"intent": INTENT}).json()) == 900
    assert window(post(sc, {"intent": INTENT, "validSeconds": 0}).json()) == 900
    assert window(post(sc, {"intent": INTENT, "validSeconds": 60}).json()) == 60
    assert window(post(sc, {"intent": INTENT, "validSeconds": 7200}).json()) == 7200
    assert window(post(sc, {"intent": INTENT, "valid_seconds": 1800}).json()) == 1800

    refused = post(sc, {"intent": INTENT, "validSeconds": 7201})
    assert refused.status == 400
    assert b"7200" in refused.body and b"900" in refused.body


@pytest.mark.parametrize("seconds", [30, 300, 3600])
def test_changing_the_default_changes_what_callers_get(seconds):
    sc, _ = make(default_valid_seconds=seconds, max_valid_seconds=3600)
    assert window(post(sc, {"intent": INTENT}).json()) == seconds


def test_a_default_past_the_maximum_is_refused_at_startup():
    with pytest.raises(SidecarError):
        make(default_valid_seconds=7200, max_valid_seconds=3600)
    with pytest.raises(SidecarError):
        make(default_valid_seconds=0, max_valid_seconds=3600)


@pytest.mark.parametrize(
    "text,seconds",
    [("90", 90), ("90s", 90), ("5m", 300), ("1h", 3600), ("1h30m", 5400), (" 2H ", 7200)],
)
def test_parse_duration(text, seconds):
    assert sidecar.parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "soon", "5 minutes", "1d", "-5m", "5m30", "m5", "1.5h"])
def test_parse_duration_rejects_other_text(text):
    with pytest.raises(SidecarError):
        sidecar.parse_duration(text)


def test_validity_window():
    assert sidecar.validity_window("10m", "2h") == (600, 7200)
    assert sidecar.validity_window("1h", "1h") == (3600, 3600)
    for default, maximum in (("2h", "1h"), ("0s", "1h"), ("0", "1h")):
        with pytest.raises(SidecarError):
            sidecar.validity_window(default, maximum)


# ---------------------------------------------------------------------------
# Token, allow-list, host check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        None,
        "Bearer wrong-horse",
        "Bearer ",
        "correct-horse",
        "Basic correct-horse",
        "Bearer correct-horse-and-more",
        "Bearer correct",
        "bearer correct-horse",
    ],
)
def test_wrong_tokens_are_refused(header):
    sc, _ = make(token="correct-horse")
    headers = {"Authorization": header} if header is not None else {}
    response = post(sc, {"intent": INTENT}, headers=headers)
    assert response.status == 401 and response.www_authenticate


def test_the_right_token_signs_and_public_endpoints_stay_open():
    sc, _ = make(token="correct-horse")
    assert (
        post(sc, {"intent": INTENT}, headers={"Authorization": "Bearer correct-horse"}).status
        == 200
    )
    assert get(sc, "/health").status == 200
    assert get(sc, "/pubkey").status == 200


def test_allowlist_is_enforced():
    sc, _ = make(allowed_actions=frozenset({"read.file"}))
    assert post(sc, {"intent": INTENT}).status == 200
    for action in ("ledger.transfer", "READ.FILE", "read.file ", "read"):
        response = post(sc, {"intent": {**INTENT, "action": action}})
        assert response.status == 403, action
        assert post(sc, {"intent": {**INTENT, "action": action}}, path="/sign/hybrid").status == 403


@pytest.mark.parametrize(
    "host",
    ["evil.example:8877", "evil.example", "127.0.0.1.evil.example:8877", "10.0.0.5:8877", ""],
)
def test_local_sidecar_ignores_foreign_host_names(host):
    sc, _ = make()
    for path, method in (("/sign", "POST"), ("/pubkey", "GET"), ("/health", "GET")):
        body = json.dumps({"intent": INTENT}).encode() if method == "POST" else b""
        assert sc.handle(method, path, {**HEADERS, "Host": host}, body).status == 403


@pytest.mark.parametrize(
    "host", ["localhost:8877", "127.0.0.1:8877", "[::1]:8877", "localhost", "::1"]
)
def test_local_host_names_are_served(host):
    sc, _ = make()
    assert post(sc, {"intent": INTENT}, headers={"Host": host}).status == 200


def test_a_shared_sidecar_is_reached_by_name_and_relies_on_the_token():
    sc, _ = make(token="t0ken", loopback_only=False)
    headers = {"Host": "vouch-sidecar:8877", "Authorization": "Bearer t0ken"}
    assert post(sc, {"intent": INTENT}, headers=headers).status == 200
    assert post(sc, {"intent": INTENT}, headers={"Host": "vouch-sidecar:8877"}).status == 401


def test_check_exposure():
    for host in ("127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.53"):
        sidecar.check_exposure(host, "")
    for host in ("0.0.0.0", "", "::", "192.168.1.20", "sidecar.internal", "127.0.0.1.example.com"):
        with pytest.raises(SidecarError):
            sidecar.check_exposure(host, "")
        sidecar.check_exposure(host, "s3cret")


def test_load_allowlist(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {"issuer": DID, "actions": [{"name": "read.file"}, {"name": "http.post"}, {"name": ""}]}
        )
    )
    assert sidecar.load_allowlist(str(good), DID) == frozenset({"read.file", "http.post"})

    with pytest.raises(SidecarError):
        sidecar.load_allowlist(str(good), "did:web:someone-else.example")
    for name, content in (
        ("empty.json", '{"actions": []}'),
        ("bad.json", '{"actions":'),
        ("list.json", "[]"),
    ):
        path = tmp_path / name
        path.write_text(content)
        with pytest.raises(SidecarError):
            sidecar.load_allowlist(str(path), DID)
    with pytest.raises(SidecarError):
        sidecar.load_allowlist(str(tmp_path / "missing.json"), DID)


# ---------------------------------------------------------------------------
# Post-quantum proof set
# ---------------------------------------------------------------------------


def suites(credential):
    proof = credential["proof"]
    return [p["cryptosuite"] for p in (proof if isinstance(proof, list) else [proof])]


def test_hybrid_mode_signs_with_both_proofs():
    keys = generate_identity("agent.example.com")
    plain, _ = make(keys)
    hybrid, _ = make(keys, hybrid=True)

    assert suites(post(plain, {"intent": INTENT}).json()) == ["eddsa-jcs-2022"]
    for credential in (
        post(hybrid, {"intent": INTENT}).json(),
        post(plain, {"intent": INTENT}, path="/sign/hybrid").json(),
    ):
        assert sorted(suites(credential)) == ["eddsa-jcs-2022", "mldsa44-jcs-2024"]


def test_hybrid_credential_needs_both_keys_to_verify():
    sc, keys = make(hybrid=True)
    credential = post(sc, {"intent": INTENT}).json()
    pq_key = get(sc, "/pubkey").json()["mldsa44"]["publicKeyMultibase"]

    ok, _ = vouch.Verifier.verify(
        credential, public_key=keys.public_key_jwk, mldsa44_public_key=pq_key
    )
    assert ok

    other, _ = make(hybrid=True)
    other_pq = get(other, "/pubkey").json()["mldsa44"]["publicKeyMultibase"]
    assert not vouch.Verifier.verify(
        credential, public_key=keys.public_key_jwk, mldsa44_public_key=other_pq
    )[0]

    altered = copy.deepcopy(credential)
    altered["credentialSubject"]["intent"]["action"] = "ledger.transfer"
    assert not vouch.Verifier.verify(
        altered, public_key=keys.public_key_jwk, mldsa44_public_key=pq_key
    )[0]

    # With only the Ed25519 key at hand the second proof cannot be checked.
    with pytest.raises(MissingMLDSA44KeyError):
        vouch.Verifier.verify(credential, public_key=keys.public_key_jwk)


def test_post_quantum_key_is_published_in_hybrid_mode():
    keys = generate_identity("agent.example.com")
    plain, _ = make(keys)
    hybrid, _ = make(keys, hybrid=True)

    assert len(get(plain, "/.well-known/did.json").json()["verificationMethod"]) == 1
    document = get(hybrid, "/.well-known/did.json").json()
    first, second = document["verificationMethod"]
    assert first["id"] == f"{DID}#key-1" and second["id"] == f"{DID}#key-2"
    assert second["type"] == "Multikey"
    assert vouch.multikey.decode(second["publicKeyMultibase"])[0] == "ML-DSA-44"
    assert document["assertionMethod"] == [f"{DID}#key-1", f"{DID}#key-2"]


# ---------------------------------------------------------------------------
# Read-only endpoints, health, logs
# ---------------------------------------------------------------------------


def test_read_only_endpoints():
    sc, keys = make(key_source=sidecar.KEY_EPHEMERAL)

    assert get(sc, "/did").json() == {"did": DID, "verificationMethod": f"{DID}#key-1"}
    document = get(sc, "/.well-known/did.json").json()
    assert document["id"] == DID
    method = document["verificationMethod"][0]
    assert method == {
        "id": f"{DID}#key-1",
        "type": "Multikey",
        "controller": DID,
        "publicKeyMultibase": get(sc, "/pubkey").json()["publicKeyMultibase"],
    }
    private_d = json.loads(keys.private_key_jwk)["d"]
    for path in ("/health", "/did", "/pubkey", "/.well-known/did.json"):
        assert private_d not in get(sc, path).body.decode()


def test_health_reports_the_last_signature():
    sc, _ = make(
        key_source=sidecar.KEY_FROM_KEYSTORE, default_valid_seconds=120, max_valid_seconds=600
    )

    before = get(sc, "/health").json()
    assert before["ready"] is True and before["lastSignedAt"] is None
    assert before["key"] == "keystore"
    assert (before["defaultValiditySeconds"], before["maxValiditySeconds"]) == (120, 600)

    post(sc, {})  # refused: not a signature
    assert get(sc, "/health").json()["lastSignedAt"] is None

    post(sc, {"intent": INTENT})
    assert get(sc, "/health").json()["lastSignedAt"].endswith("Z")


def test_logs_are_json_and_carry_no_secrets():
    log = io.StringIO()
    sc, keys = make(log=log, token="s3cret-token-value", verbose=True)

    post(sc, {"intent": INTENT}, headers={"Authorization": "Bearer s3cret-token-value"})
    post(sc, {"intent": INTENT}, headers={"Authorization": "Bearer wrong-guess"})
    get(sc, "/health")

    lines = [json.loads(line) for line in log.getvalue().splitlines()]
    signed = next(line for line in lines if line["msg"] == "signed")
    refused = next(line for line in lines if line["msg"] == "refused")
    assert signed["action"] == "read.file" and signed["did"] == DID
    assert signed["credential_id"].startswith("urn:uuid:") and signed["proof"] == "eddsa-jcs-2022"
    assert refused["status"] == 401 and refused["reason"]
    assert sum(1 for line in lines if line["msg"] == "request") == 3

    text = log.getvalue()
    private_d = json.loads(keys.private_key_jwk)["d"]
    for secret in ("s3cret-token-value", "wrong-guess", "customer-8842", private_d, "proofValue"):
        assert secret not in text


def test_quiet_mode_logs_signatures_only():
    log = io.StringIO()
    sc, _ = make(log=log)
    get(sc, "/health")
    post(sc, {"intent": {**INTENT, "action": "a" * 5000}})
    lines = [json.loads(line) for line in log.getvalue().splitlines()]
    assert [line["msg"] for line in lines] == ["signed"]
    assert len(lines[0]["action"]) <= sidecar.MAX_LOGGED_TEXT


# ---------------------------------------------------------------------------
# Which identity: the keystore by default, with nothing to pass
# ---------------------------------------------------------------------------


def test_one_identity_in_the_keystore_needs_no_flags(temp_keystore):
    keys = stored()
    identity = sidecar.resolve_identity(environ={})
    assert identity.did == DID and identity.source == sidecar.KEY_FROM_KEYSTORE
    assert json.loads(identity.private_jwk)["d"] == json.loads(keys.private_key_jwk)["d"]


def test_identity_is_found_by_did(temp_keystore):
    stored("other.example.com")
    keys = stored()
    identity = sidecar.resolve_identity(did=DID, environ={})
    assert json.loads(identity.private_jwk)["d"] == json.loads(keys.private_key_jwk)["d"]


def test_several_identities_need_a_choice(temp_keystore):
    stored("a.example.com")
    stored("b.example.com")
    with pytest.raises(SidecarError) as error:
        sidecar.resolve_identity(environ={})
    assert "did:web:a.example.com" in str(error.value) and "--did" in str(error.value)


@pytest.mark.parametrize("did", [None, DID])
def test_no_key_anywhere_fails(temp_keystore, did):
    with pytest.raises(SidecarError) as error:
        sidecar.resolve_identity(did=did, environ={})
    assert "no signing key" in str(error.value) and "--dev" in str(error.value)


@pytest.mark.parametrize(
    "lookalike",
    ["did-web-agent.example.com", "did/web/agent.example.com", "../did-web-agent.example.com"],
)
def test_keystore_file_must_name_the_requested_did(temp_keystore, lookalike):
    stored()
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(did=lookalike, environ={})


def test_locked_identity_opens_with_the_passphrase(temp_keystore):
    keys = stored(password="correct horse battery staple")
    asked = []

    def ask(did):
        asked.append(did)
        return "correct horse battery staple"

    identity = sidecar.resolve_identity(environ={}, ask_passphrase=ask)
    assert asked == [DID]
    assert json.loads(identity.private_jwk)["d"] == json.loads(keys.private_key_jwk)["d"]

    from_env = sidecar.resolve_identity(
        environ={sidecar.PASSPHRASE_ENV: "correct horse battery staple"}
    )
    assert from_env.did == DID


def test_locked_identity_refuses_a_wrong_or_missing_passphrase(temp_keystore):
    stored(password="correct horse battery staple")
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(environ={}, ask_passphrase=lambda did: "wrong")
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(environ={}, ask_passphrase=lambda did: "")
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(environ={})


# ---------------------------------------------------------------------------
# Explicit key sources and --dev
# ---------------------------------------------------------------------------


def test_key_file_names_its_own_did(temp_keystore, tmp_path):
    keys = generate_identity("agent.example.com")
    path = tmp_path / "identity.json"
    path.write_text(
        json.dumps({"id": DID, "encrypted": False, "private_key": keys.private_key_jwk})
    )

    identity = sidecar.resolve_identity(key_path=str(path), environ={})
    assert identity.did == DID and identity.source == sidecar.KEY_FROM_FILE
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(key_path=str(path), did="did:web:someone-else.example", environ={})


def test_bare_jwk_needs_a_did(temp_keystore, tmp_path):
    path = tmp_path / "agent.jwk"
    path.write_text(generate_identity().private_key_jwk)
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(key_path=str(path), environ={})
    assert sidecar.resolve_identity(key_path=str(path), did=DID, environ={}).did == DID
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(key_path=str(tmp_path / "missing.jwk"), did=DID, environ={})


def test_bad_key_files_are_refused(temp_keystore, tmp_path):
    good = json.loads(generate_identity().private_key_jwk)
    other = json.loads(generate_identity().private_key_jwk)
    cases = {
        "not json": "not json",
        "list": "[]",
        "wrong curve": json.dumps({**good, "crv": "X25519"}),
        "wrong type": json.dumps({**good, "kty": "EC"}),
        "public only": json.dumps({k: v for k, v in good.items() if k != "d"}),
        "short key": json.dumps({**good, "d": good["d"][:20]}),
        "mismatched public": json.dumps({**good, "x": other["x"]}),
        "locked": json.dumps({"id": DID, "encrypted": True, "cipher": {"ciphertext": "AAAA"}}),
        "empty": "{}",
    }
    for name, content in cases.items():
        path = tmp_path / "key.json"
        path.write_text(content)
        with pytest.raises(SidecarError):
            sidecar.resolve_identity(key_path=str(path), did=DID, environ={})
            pytest.fail(f"{name}: accepted")


def test_environment_keys(temp_keystore):
    keys = generate_identity("agent.example.com")
    from_jwk = sidecar.resolve_identity(
        environ={sidecar.PRIVATE_KEY_ENV: keys.private_key_jwk, sidecar.DID_ENV: DID}
    )
    assert from_jwk.did == DID and from_jwk.source == sidecar.KEY_FROM_ENV

    seed = bytes(range(100, 132))
    from_seed = sidecar.resolve_identity(did=DID, environ={sidecar.SEED_ENV: seed.hex().upper()})
    assert sidecar._b64url_decode(json.loads(from_seed.private_jwk)["d"]) == seed

    with pytest.raises(SidecarError):
        sidecar.resolve_identity(environ={sidecar.SEED_ENV: seed.hex()})  # no DID
    for bad in ("zz" * 32, "abcd", "ab" * 33):
        with pytest.raises(SidecarError) as error:
            sidecar.resolve_identity(did=DID, environ={sidecar.SEED_ENV: bad})
        assert bad not in str(error.value)


def test_two_explicit_key_sources_are_refused(temp_keystore, tmp_path):
    path = tmp_path / "agent.jwk"
    path.write_text(generate_identity().private_key_jwk)
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(key_path=str(path), did=DID, environ={sidecar.SEED_ENV: "ab" * 32})


def test_dev_mode_uses_a_fresh_random_key(temp_keystore):
    saved = stored()
    first = sidecar.resolve_identity(did=DID, dev=True, environ={})
    second = sidecar.resolve_identity(did=DID, dev=True, environ={})
    assert first.source == sidecar.KEY_EPHEMERAL
    keys = {
        json.loads(k)["d"] for k in (first.private_jwk, second.private_jwk, saved.private_key_jwk)
    }
    assert len(keys) == 3
    with pytest.raises(SidecarError):
        sidecar.resolve_identity(dev=True, environ={})


def test_an_explicit_key_wins_over_the_keystore_and_dev(temp_keystore, tmp_path):
    stored()
    explicit = generate_identity("agent.example.com")
    path = tmp_path / "agent.jwk"
    path.write_text(explicit.private_key_jwk)
    identity = sidecar.resolve_identity(key_path=str(path), did=DID, dev=True, environ={})
    assert identity.source == sidecar.KEY_FROM_FILE
    assert json.loads(identity.private_jwk)["d"] == json.loads(explicit.private_key_jwk)["d"]


# ---------------------------------------------------------------------------
# Command line and the real HTTP server
# ---------------------------------------------------------------------------


def parse(*argv):
    parser = argparse.ArgumentParser()
    sidecar.add_arguments(parser)
    return parser.parse_args(list(argv))


def test_build_sidecar_from_flags(temp_keystore, tmp_path, monkeypatch):
    stored()
    allowlist = tmp_path / "vouch-allowlist.json"
    allowlist.write_text(json.dumps({"issuer": DID, "actions": [{"name": "read.file"}]}))

    sc = sidecar.build_sidecar(
        parse("--allowlist", str(allowlist), "--default-validity", "10m", "--max-validity", "2h")
    )
    assert sc.config.did == DID and sc.config.key_source == "keystore"
    assert (sc.config.default_valid_seconds, sc.config.max_valid_seconds) == (600, 7200)
    assert window(post(sc, {"intent": INTENT}).json()) == 600
    assert post(sc, {"intent": {**INTENT, "action": "ledger.transfer"}}).status == 403

    monkeypatch.setenv(sidecar.DEFAULT_VALIDITY_ENV, "90s")
    assert sidecar.build_sidecar(parse()).config.default_valid_seconds == 90


@pytest.mark.parametrize(
    "argv",
    [
        ["--host", "0.0.0.0"],
        ["--default-validity", "2h", "--max-validity", "1h"],
        ["--default-validity", "soon"],
        ["--allowlist", "/nonexistent/vouch-allowlist.json"],
        ["--did", "did:web:nobody.example.com"],
    ],
)
def test_bad_settings_stop_startup(temp_keystore, argv, capsys):
    stored()
    assert sidecar.run(parse(*argv)) == 1
    assert "vouch sidecar:" in capsys.readouterr().err


def test_startup_without_a_key_fails(temp_keystore, capsys):
    assert sidecar.run(parse()) == 1
    assert "no signing key" in capsys.readouterr().err


def test_secrets_are_dropped_from_the_environment(temp_keystore, monkeypatch):
    keys = generate_identity("agent.example.com")
    monkeypatch.setenv(sidecar.PRIVATE_KEY_ENV, keys.private_key_jwk)
    monkeypatch.setenv(sidecar.DID_ENV, DID)
    monkeypatch.setenv(sidecar.TOKEN_ENV, "t0ken")
    sc = sidecar.build_sidecar(parse("--host", "0.0.0.0"))
    import os

    assert sidecar.PRIVATE_KEY_ENV not in os.environ and sidecar.TOKEN_ENV not in os.environ
    assert sc.config.token == "t0ken" and sc.config.loopback_only is False


def test_cli_has_the_sidecar_command_and_valid_for(temp_keystore, capsys):
    with pytest.raises(SystemExit):
        cli.main(["sidecar", "--help"])
    help_text = capsys.readouterr().out
    for flag in (
        "--did",
        "--allowlist",
        "--default-validity",
        "--max-validity",
        "--hybrid",
        "--dev",
    ):
        assert flag in help_text

    stored()
    args = types.SimpleNamespace(
        message="approve order 42", json=False, key=None, did=None, header=False
    )
    for valid_for, seconds in (("2h", 7200), ("45", 45), (None, 300)):
        args.valid_for = valid_for
        assert cli.cmd_sign(args) == 0
        assert window(json.loads(capsys.readouterr().out)) == seconds
    args.valid_for = "soon"
    assert cli.cmd_sign(args) == 1


def test_vouch_bridge_with_a_did_runs_the_sidecar(monkeypatch):
    pytest.importorskip("fastapi")
    from vouch.bridge import server as bridge

    seen = {}
    monkeypatch.setattr(sidecar, "main", lambda argv: seen.setdefault("argv", argv) and 0)
    monkeypatch.setattr("sys.argv", ["vouch-bridge", "--did", DID, "--port", "8877"])
    with pytest.raises(SystemExit) as stop:
        bridge.main()
    assert stop.value.code == 0
    assert seen["argv"] == ["--did", DID, "--port", "8877"]


@pytest.fixture
def running(temp_keystore):
    """A sidecar listening on a free local port."""
    keys = stored()
    sc = sidecar.build_sidecar(parse())
    server = sidecar.make_server(sc, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", keys
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def http(url, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_over_real_http(running):
    base, keys = running
    json_headers = {"Content-Type": "application/json"}

    status, body = http(f"{base}/sign", json.dumps({"intent": INTENT}).encode(), json_headers)
    assert status == 200
    assert vouch.verify(json.loads(body), keys.public_key_jwk)[0]

    assert http(f"{base}/health")[0] == 200
    assert http(f"{base}/sign")[0] == 405
    assert http(f"{base}/sign", b"{}", json_headers)[0] == 400
    assert http(f"{base}/sign", json.dumps({"intent": INTENT}).encode())[0] == 415
    assert http(f"{base}/nothing")[0] == 404
    assert http(f"{base}/pubkey", headers={"Host": "evil.example"})[0] == 403

    # An oversized body is refused before it is read: the caller sees a 400 or
    # a closed connection, and the sidecar keeps serving.
    huge = json.dumps(
        {"intent": {**INTENT, "resource": "x" * (sidecar.MAX_BODY_BYTES + 1)}}
    ).encode()
    try:
        assert http(f"{base}/sign", huge, json_headers)[0] == 400
    except urllib.error.URLError:
        pass
    assert http(f"{base}/health")[0] == 200
