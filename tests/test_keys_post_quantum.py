"""
Tests for the saved post-quantum key.

An identity keeps two keys: its Ed25519 key and an ML-DSA-44 key. Both are saved
in the identity file, so the same pair signs on every run and the published
"#key-2" stays true. These tests cover saving and reloading, identities from
before the second key was saved, and what happens when the file is altered.
"""

import base64
import copy
import json
import os
import threading
import types

import pytest

pytest.importorskip("pqcrypto.sign.ml_dsa_44", reason="post-quantum package not installed")

import vouch  # noqa: E402
from vouch import cli, sidecar  # noqa: E402
from vouch.keys import (  # noqa: E402
    MLDSA44,
    MLDSA44_KEY_ID,
    KeyManager,
    StoredKey,
    generate_identity,
    new_post_quantum_key,
)

DID = "did:web:agent.example.com"
PASSWORD = "correct horse battery staple"
INTENT = {"action": "read.file", "target": "report", "resource": "https://api.example.com/r/1"}


@pytest.fixture
def km(tmp_path):
    return KeyManager(str(tmp_path))


@pytest.fixture
def temp_keystore(tmp_path, monkeypatch):
    """Point every KeyManager() at a temp directory."""
    orig_init = KeyManager.__init__
    monkeypatch.setattr(
        KeyManager, "__init__", lambda self, key_dir=str(tmp_path): orig_init(self, str(tmp_path))
    )
    for name in (sidecar.SEED_ENV, sidecar.PRIVATE_KEY_ENV, sidecar.DID_ENV, sidecar.TOKEN_ENV):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def saved(km, password=None, post_quantum=True):
    keys = generate_identity("agent.example.com", post_quantum=post_quantum)
    km.save_identity(keys, password)
    return keys


def read(km, did=DID):
    with open(km._get_filename(did)) as f:
        return json.load(f)


def write(km, data, did=DID):
    with open(km._get_filename(did), "w") as f:
        json.dump(data, f)


def pq(keys):
    return keys.key_for(MLDSA44)


def hybrid_verifies(credential, keys, pq_public):
    return vouch.Verifier.verify(
        credential, public_key=keys.public_key_jwk, mldsa44_public_key=pq_public
    )[0]


# ---------------------------------------------------------------------------
# The same key on every run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_both_keys_survive_a_save_and_reload(km, password):
    keys = saved(km, password)

    first, second = km.load_identity(DID, password), km.load_identity(DID, password)

    assert pq(first).public_key == pq(second).public_key == pq(keys).public_key
    assert pq(first).private_key == pq(keys).private_key
    assert pq(first).id == MLDSA44_KEY_ID
    assert first.private_key_jwk == keys.private_key_jwk


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_a_later_run_publishes_the_key_an_earlier_run_signed_with(km, password):
    saved(km, password)
    run_one = vouch.Signer.from_keypair(km.load_identity(DID, password))
    run_two = vouch.Signer.from_keypair(km.load_identity(DID, password))

    credential = run_one.sign_hybrid(intent=INTENT)

    assert run_one.public_key_mldsa44_multikey() == run_two.public_key_mldsa44_multikey()
    assert hybrid_verifies(
        credential, km.load_identity(DID, password), run_two.public_key_mldsa44_multikey()
    )
    assert run_one.has_saved_mldsa44_key()


def test_a_signer_without_a_saved_key_still_makes_one_per_process():
    keys = generate_identity("agent.example.com")
    one, two = vouch.Signer.from_keypair(keys), vouch.Signer.from_keypair(keys)

    assert not one.has_saved_mldsa44_key()
    assert one.public_key_mldsa44_multikey() != two.public_key_mldsa44_multikey()


def test_locked_file_keeps_the_post_quantum_private_key_locked(km):
    keys = saved(km, PASSWORD)
    data = read(km)
    row = data["keys"][0]

    assert data["v"] == 2 and data["encrypted"] is True
    assert "private_key" not in row and "private_key" not in data
    raw = json.dumps(data)
    assert base64.b64encode(pq(keys).private_key).decode() not in raw
    assert json.loads(keys.private_key_jwk)["d"] not in raw
    assert oct(os.stat(km._get_filename(DID)).st_mode & 0o777) == "0o600"


def test_an_identity_with_one_key_is_written_as_before(km):
    saved(km, post_quantum=False)
    data = read(km)
    assert data["v"] == 1 and "keys" not in data
    assert km.load_identity(DID).additional_keys == []


def test_an_earlier_reader_still_opens_the_file(km):
    """A reader from before the key list reads the fields it always read."""
    keys = saved(km)
    data = read(km)
    assert data["id"] == DID and data["public_key"] == keys.public_key_jwk
    assert data["private_key"] == keys.private_key_jwk


# ---------------------------------------------------------------------------
# Identities from before the second key was saved
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_an_older_identity_gains_the_key_once_and_keeps_it(km, password):
    old = saved(km, password, post_quantum=False)

    first = km.ensure_post_quantum_key(DID, password)
    second = km.ensure_post_quantum_key(DID, password)

    assert pq(first).public_key == pq(second).public_key
    assert first.private_key_jwk == old.private_key_jwk
    assert pq(km.load_identity(DID, password)).public_key == pq(first).public_key
    assert not os.path.exists(km._get_filename(DID) + ".lock")


def test_adding_the_key_needs_the_right_passphrase(km):
    saved(km, PASSWORD, post_quantum=False)
    before = read(km)

    with pytest.raises(ValueError):
        km.ensure_post_quantum_key(DID, None)
    with pytest.raises(ValueError):
        km.ensure_post_quantum_key(DID, "wrong")

    assert read(km) == before
    assert not os.path.exists(km._get_filename(DID) + ".lock")


def test_two_programs_adding_the_key_at_once_agree(km):
    saved(km, post_quantum=False)
    results, errors = [], []

    def add():
        try:
            results.append(pq(km.ensure_post_quantum_key(DID)).public_key)
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)

    threads = [threading.Thread(target=add) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == []
    assert len(results) == 6 and len(set(results)) == 1
    assert pq(km.load_identity(DID)).public_key == results[0]


def test_an_interrupted_save_leaves_the_previous_file_intact(km, monkeypatch):
    keys = saved(km)
    before = read(km)

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    replacement = generate_identity("agent.example.com", post_quantum=True)
    with pytest.raises(OSError):
        km.save_identity(replacement)
    monkeypatch.undo()

    assert read(km) == before
    assert km.load_identity(DID).private_key_jwk == keys.private_key_jwk
    assert [name for name in os.listdir(km.key_dir) if name.endswith(".tmp")] == []


# ---------------------------------------------------------------------------
# An altered file
# ---------------------------------------------------------------------------


def test_a_swapped_public_key_is_caught(km):
    saved(km)
    data = read(km)
    data["keys"][0]["public_key"] = new_post_quantum_key().public_key
    write(km, data)

    with pytest.raises(ValueError, match="does not match"):
        km.load_identity(DID)


def test_a_swapped_private_key_is_caught(km):
    saved(km)
    data = read(km)
    data["keys"][0]["private_key"] = base64.b64encode(new_post_quantum_key().private_key).decode()
    write(km, data)

    with pytest.raises(ValueError):
        km.load_identity(DID)


@pytest.mark.parametrize(
    "change",
    [
        lambda row: row.update(public_key=new_post_quantum_key().public_key),
        lambda row: row["cipher"].update(ciphertext=base64.b64encode(b"\x00" * 2576).decode()),
        lambda row: row["cipher"].update(nonce=base64.b64encode(b"\x01" * 12).decode()),
        lambda row: row["cipher"].update(ciphertext=row["cipher"]["ciphertext"][:-8]),
        lambda row: row.update(private_key=base64.b64encode(b"\x00" * 2560).decode()),
    ],
    ids=["public key", "ciphertext", "nonce", "truncated", "plaintext added"],
)
def test_a_locked_row_cannot_be_altered(km, change):
    saved(km, PASSWORD)
    data = read(km)
    change(data["keys"][0])
    write(km, data)

    with pytest.raises(ValueError):
        km.load_identity(DID, PASSWORD)


def test_a_locked_row_cannot_be_moved_to_another_identity(km):
    """Same passphrase, same person, two agents: one agent's saved key is no
    use in the other agent's file."""
    saved(km, PASSWORD)
    other = generate_identity("other.example.com", post_quantum=True)
    km.save_identity(other, PASSWORD)

    # Give the second file the first file's salt and Ed25519 ciphertext too, so
    # only the row's own binding stands between the two identities.
    donor, target = read(km), read(km, other.did)
    moved = copy.deepcopy(donor)
    moved["id"] = other.did
    write(km, moved, other.did)

    with pytest.raises(ValueError):
        km.load_identity(other.did, PASSWORD)
    assert target["id"] == other.did


@pytest.mark.parametrize(
    "keys_field",
    [
        "not a list",
        ["not an object"],
        [{"id": MLDSA44_KEY_ID, "alg": MLDSA44}],
        [{"id": "#key-9", "alg": MLDSA44, "public_key": "z", "private_key": "AAAA"}],
        [{"id": MLDSA44_KEY_ID, "alg": MLDSA44, "public_key": "z", "private_key": "!!!"}],
        [{"id": MLDSA44_KEY_ID, "alg": MLDSA44, "public_key": 7, "private_key": "AAAA"}],
    ],
)
def test_a_malformed_key_list_is_an_error_not_a_new_key(km, keys_field):
    saved(km, post_quantum=False)
    data = read(km)
    data["keys"] = keys_field
    write(km, data)

    with pytest.raises(ValueError):
        km.load_identity(DID)
    # A damaged entry must not be papered over with a fresh key.
    with pytest.raises(ValueError):
        km.ensure_post_quantum_key(DID)
    assert read(km)["keys"] == keys_field


def test_two_post_quantum_rows_are_refused(km):
    saved(km)
    data = read(km)
    data["keys"].append(copy.deepcopy(data["keys"][0]))
    write(km, data)

    with pytest.raises(ValueError, match="two"):
        km.load_identity(DID)


def test_a_key_type_from_a_later_release_is_left_alone(km):
    keys = saved(km)
    data = read(km)
    data["keys"].insert(
        0, {"id": "#key-3", "alg": "SLH-DSA-128s", "public_key": "z", "private_key": "AA=="}
    )
    write(km, data)

    loaded = km.load_identity(DID)
    assert [key.alg for key in loaded.additional_keys] == [MLDSA44]
    assert pq(loaded).public_key == pq(keys).public_key


def test_saving_refuses_a_key_whose_halves_do_not_belong_together(km):
    keys = generate_identity("agent.example.com")
    a, b = new_post_quantum_key(), new_post_quantum_key()
    keys.additional_keys.append(StoredKey(MLDSA44_KEY_ID, MLDSA44, a.public_key, b.private_key))
    with pytest.raises(ValueError):
        km.save_identity(keys)

    keys.additional_keys = [a, b]
    with pytest.raises(ValueError):
        km.save_identity(keys)
    assert not os.path.exists(km._get_filename(DID))


def test_the_signer_refuses_a_key_of_the_wrong_size():
    keys = generate_identity("agent.example.com")
    with pytest.raises(ValueError):
        vouch.Signer(keys.private_key_jwk, DID, mldsa44_keypair=(b"short", b"short"))


def test_the_private_key_is_not_printed_with_the_identity():
    key = new_post_quantum_key()
    assert base64.b64encode(key.private_key).decode()[:40] not in repr(key)
    assert "private_key" not in repr(key)


# ---------------------------------------------------------------------------
# vouch init, the sidecar, and auto-signing
# ---------------------------------------------------------------------------


def init(domain="agent.example.com"):
    return cli.cmd_init(types.SimpleNamespace(domain=domain, env=False, yes=True))


def test_vouch_init_creates_both_keys(temp_keystore, capsys):
    assert init() == 0
    loaded = KeyManager().load_identity(DID)
    assert pq(loaded) is not None and pq(loaded).id == MLDSA44_KEY_ID


def test_vouch_init_again_keeps_the_identity(temp_keystore, capsys):
    assert init() == 0
    before = KeyManager().load_identity(DID)

    assert init() == 0

    after = KeyManager().load_identity(DID)
    assert after.private_key_jwk == before.private_key_jwk
    assert pq(after).public_key == pq(before).public_key
    assert "already exists" in capsys.readouterr().out


def test_vouch_init_adds_the_key_to_an_older_identity(temp_keystore, capsys):
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)

    assert init() == 0

    upgraded = KeyManager().load_identity(DID)
    assert upgraded.private_key_jwk == old.private_key_jwk
    assert pq(upgraded) is not None
    assert "Added a post-quantum key" in capsys.readouterr().out


def test_vouch_init_leaves_a_locked_identity_alone_without_a_terminal(temp_keystore, capsys):
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old, PASSWORD)
    before = read(KeyManager())

    assert init() == 0

    assert read(KeyManager()) == before
    assert "locked" in capsys.readouterr().out


def parse(*argv):
    import argparse

    parser = argparse.ArgumentParser()
    sidecar.add_arguments(parser)
    return parser.parse_args(list(argv))


def post(sc, path="/sign/hybrid"):
    headers = {"Host": "127.0.0.1:8877", "Content-Type": "application/json"}
    return sc.handle("POST", path, headers, json.dumps({"intent": INTENT}).encode())


def test_two_sidecar_runs_publish_the_same_post_quantum_key(temp_keystore):
    init()
    run_one = sidecar.build_sidecar(parse("--hybrid"))
    run_two = sidecar.build_sidecar(parse("--hybrid"))
    headers = {"Host": "127.0.0.1:8877"}

    credential = post(run_one, "/sign").json()
    published = run_two.handle("GET", "/pubkey", headers, b"").json()["mldsa44"][
        "publicKeyMultibase"
    ]

    assert hybrid_verifies(credential, KeyManager().load_identity(DID), published)
    assert (
        run_one.handle("GET", "/.well-known/did.json", headers, b"").json()
        == run_two.handle("GET", "/.well-known/did.json", headers, b"").json()
    )
    assert run_one.handle("GET", "/health", headers, b"").json()["postQuantumKey"] == "saved"


def test_hybrid_sidecar_upgrades_an_older_identity_once(temp_keystore):
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)

    sidecar.build_sidecar(parse("--hybrid"))
    first = pq(KeyManager().load_identity(DID)).public_key
    sidecar.build_sidecar(parse("--hybrid"))

    assert pq(KeyManager().load_identity(DID)).public_key == first
    assert KeyManager().load_identity(DID).private_key_jwk == old.private_key_jwk


def test_sidecar_without_a_saved_key_refuses_post_quantum_signing(temp_keystore, tmp_path):
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)

    plain = sidecar.build_sidecar(parse())  # not started with --hybrid
    refused = post(plain)
    assert refused.status == 409 and b"post-quantum key" in refused.body
    assert post(plain, "/sign").status == 200
    assert pq(KeyManager().load_identity(DID)) is None  # nothing was created on the side

    bare = tmp_path / "agent.jwk"
    bare.write_text(old.private_key_jwk)
    with pytest.raises(sidecar.SidecarError):
        sidecar.build_sidecar(parse("--key", str(bare), "--did", DID, "--hybrid"))


def test_dev_mode_still_uses_a_key_for_one_run(temp_keystore):
    dev = sidecar.build_sidecar(parse("--did", DID, "--dev"))
    assert post(dev).status == 200
    assert dev.config.post_quantum == "per-run"


def test_a_key_file_that_carries_both_keys_serves_post_quantum(temp_keystore, tmp_path):
    keys = generate_identity("agent.example.com", post_quantum=True)
    elsewhere = KeyManager(str(tmp_path / "elsewhere"))
    elsewhere.save_identity(keys)

    sc = sidecar.build_sidecar(parse("--key", elsewhere._get_filename(DID), "--hybrid"))

    credential = post(sc, "/sign").json()
    assert hybrid_verifies(credential, keys, pq(keys).public_key)


def test_auto_signing_saves_the_key_on_first_post_quantum_use(temp_keystore, monkeypatch):
    import vouch.autosign as autosign

    monkeypatch.delenv("VOUCH_AUTO_IDENTITY", raising=False)
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)

    autosign.reset_default_signer()
    signer = autosign.resolve_signer()
    assert pq(KeyManager().load_identity(DID)) is None  # nothing happens until it is needed
    credential = signer.sign_hybrid(intent=INTENT)

    stored = pq(KeyManager().load_identity(DID))
    assert stored is not None
    assert hybrid_verifies(credential, old, stored.public_key)

    autosign.reset_default_signer()
    assert autosign.resolve_signer().public_key_mldsa44_multikey() == stored.public_key
    autosign.reset_default_signer()
