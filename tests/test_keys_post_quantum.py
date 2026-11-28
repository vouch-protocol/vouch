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


def assert_not_held(km, did=DID):
    """Nobody holds the identity's lock: it can be taken straight away."""
    with km._identity_lock(did, timeout=0.5):
        pass


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
    assert_not_held(km)


def test_adding_the_key_needs_the_right_passphrase(km):
    saved(km, PASSWORD, post_quantum=False)
    before = read(km)

    with pytest.raises(ValueError):
        km.ensure_post_quantum_key(DID, None)
    with pytest.raises(ValueError):
        km.ensure_post_quantum_key(DID, "wrong")

    assert read(km) == before
    assert_not_held(km)


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

    # A save carries the unknown row through unchanged.
    km.save_identity(loaded)
    assert {
        "id": "#key-3",
        "alg": "SLH-DSA-128s",
        "public_key": "z",
        "private_key": "AA==",
    } in read(km)["keys"]


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
    KeyManager().save_identity(keys)
    outside = tmp_path / "outside" / "agent-identity.json"
    outside.parent.mkdir()
    os.replace(KeyManager()._get_filename(DID), outside)
    assert KeyManager().list_identities() == []

    sc = sidecar.build_sidecar(parse("--key", str(outside), "--hybrid"))

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


# ---------------------------------------------------------------------------
# Second review round: tampering that must never turn into a new key
# ---------------------------------------------------------------------------

from vouch.keys import (  # noqa: E402
    IdentityBusyError,
    IdentityDamagedError,
    IdentityExistsError,
    IdentityLockedError,
    WrongPasswordError,
)


def _drop_keys(d):
    d.pop("keys")


@pytest.mark.parametrize("password", [None, PASSWORD])
@pytest.mark.parametrize(
    "change",
    [
        _drop_keys,
        lambda d: d.update(keys=None),
        lambda d: d["keys"][0].update(alg="ML-DSA-65"),
        lambda d: d["keys"][0].update(alg="ml-dsa-44"),
        lambda d: d["keys"][0].pop("alg"),
        lambda d: d["keys"][0].update(alg=44),
        lambda d: d["keys"][0].update(alg="ML-DSA-44x"),
    ],
    ids=[
        "keys removed",
        "keys null",
        "alg ML-DSA-65",
        "alg lower case",
        "alg removed",
        "alg number",
        "alg one byte",
    ],
)
def test_a_tampered_post_quantum_row_is_an_error_and_never_replaced(km, password, change):
    saved(km, password)
    data = read(km)
    change(data)
    write(km, data)
    before = read(km)

    with pytest.raises(IdentityDamagedError):
        km.load_identity(DID, password)
    with pytest.raises(IdentityDamagedError):
        km.ensure_post_quantum_key(DID, password)
    assert read(km) == before


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_an_emptied_key_list_is_refused_rather_than_refilled(km, password):
    saved(km, password)
    data = read(km)
    data["keys"] = []
    write(km, data)

    assert pq(km.load_identity(DID, password)) is None
    with pytest.raises(IdentityDamagedError):
        km.ensure_post_quantum_key(DID, password)
    assert read(km)["keys"] == []


def test_damage_anywhere_in_an_unlocked_private_key_is_noticed(km):
    saved(km)
    for position in (0, 1000, 1664, 2550, 2559):
        data = read(km)
        raw = bytearray(base64.b64decode(data["keys"][0]["private_key"]))
        raw[position] ^= 0x01
        data["keys"][0]["private_key"] = base64.b64encode(bytes(raw)).decode()
        write(km, data)
        with pytest.raises(IdentityDamagedError):
            km.load_identity(DID)
        saved(km)  # a fresh, whole identity for the next position


def test_a_row_mixing_locked_and_unlocked_forms_is_refused(km):
    saved(km)
    data = read(km)
    data["keys"][0]["cipher"] = {"nonce": "AAAA", "ciphertext": "AAAA"}
    write(km, data)
    with pytest.raises(IdentityDamagedError):
        km.load_identity(DID)


def test_a_passphrase_for_an_unlocked_file_is_refused(km):
    """A locked file swapped for an unlocked one is noticed when the
    passphrase is supplied, instead of loading the swapped-in keys."""
    saved(km)
    with pytest.raises(WrongPasswordError, match="not locked"):
        km.load_identity(DID, PASSWORD)
    with pytest.raises(WrongPasswordError):
        km.ensure_post_quantum_key(DID, PASSWORD)


def test_locked_and_wrong_passphrase_are_told_apart(km):
    saved(km, PASSWORD)
    with pytest.raises(IdentityLockedError):
        km.load_identity(DID)
    with pytest.raises(WrongPasswordError):
        km.load_identity(DID, "wrong")


# ---------------------------------------------------------------------------
# The lock
# ---------------------------------------------------------------------------


def test_a_lock_file_left_behind_does_not_block(km):
    saved(km, post_quantum=False)
    with open(km._get_filename(DID) + ".lock", "w"):
        pass  # what a program that crashed would leave
    assert pq(km.ensure_post_quantum_key(DID, timeout=1)) is not None


def test_a_held_lock_times_out_as_busy(km):
    saved(km, post_quantum=False)
    with km._identity_lock(DID):
        with pytest.raises(IdentityBusyError):
            km.ensure_post_quantum_key(DID, timeout=0.3)
    assert pq(km.load_identity(DID)) is None


def test_an_identity_that_has_the_key_needs_no_lock(km):
    saved(km)
    with km._identity_lock(DID):
        assert pq(km.ensure_post_quantum_key(DID, timeout=0.3)) is not None


def test_create_identity_never_replaces_a_file(km):
    first = generate_identity("agent.example.com")
    km.create_identity(first)
    with pytest.raises(IdentityExistsError):
        km.create_identity(generate_identity("agent.example.com"))
    assert km.load_identity(DID).private_key_jwk == first.private_key_jwk


def test_old_temporary_files_are_swept_on_the_next_save(km):
    keys = saved(km)
    old = km._get_filename(DID) + ".123.abcd.tmp"
    fresh = km._get_filename(DID) + ".456.ef01.tmp"
    for path in (old, fresh):
        with open(path, "w") as f:
            f.write("{}")
    os.utime(old, (1, 1))

    km.save_identity(keys)

    assert not os.path.exists(old)
    assert os.path.exists(fresh)


def test_a_per_run_key_is_not_reported_as_saved():
    signer = vouch.Signer.from_keypair(generate_identity("agent.example.com"))
    signer.sign_hybrid(intent=INTENT)
    assert not signer.has_saved_mldsa44_key()


# ---------------------------------------------------------------------------
# What an earlier reader sees
# ---------------------------------------------------------------------------


def _earlier_reader(path, password):
    """The identity loader as it was before key lists: the main fields only,
    and the main key decrypted with no associated data."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    with open(path) as f:
        data = json.load(f)
    if not data.get("encrypted"):
        return data["id"], data["public_key"], data["private_key"]
    params = data["kdf"]["params"]
    key = Scrypt(
        salt=base64.b64decode(params["salt"]),
        length=32,
        n=params["n"],
        r=params["r"],
        p=params["p"],
    ).derive(password.encode())
    secret = ChaCha20Poly1305(key).decrypt(
        base64.b64decode(data["cipher"]["nonce"]),
        base64.b64decode(data["cipher"]["ciphertext"]),
        None,
    )
    return data["id"], data["public_key"], secret.decode()


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_an_earlier_reader_opens_a_two_key_file(km, password):
    keys = saved(km, password)
    did, public, private = _earlier_reader(km._get_filename(DID), password)
    assert (did, public, private) == (DID, keys.public_key_jwk, keys.private_key_jwk)


# ---------------------------------------------------------------------------
# Callers report damage as damage
# ---------------------------------------------------------------------------


def _damage_row(km):
    data = read(km)
    data["keys"][0]["private_key"] = data["keys"][0]["private_key"][:-8]
    write(km, data)


def test_vouch_init_reports_a_damaged_identity(temp_keystore, capsys):
    assert init() == 0
    _damage_row(KeyManager())
    before = read(KeyManager())

    assert init() == 1

    err = capsys.readouterr().err
    assert "damaged" in err and "locked" not in err
    assert read(KeyManager()) == before


def test_vouch_init_never_writes_over_a_file_it_cannot_read(temp_keystore, capsys):
    path = KeyManager()._get_filename(DID)
    with open(path, "w") as f:
        f.write('{"id": "did:web:agent.ex')  # cut short
    assert init() == 1
    assert "left as it is" in capsys.readouterr().err
    with open(path) as f:
        assert f.read() == '{"id": "did:web:agent.ex'


def test_vouch_init_does_not_take_over_a_file_name_shared_with_another_did(temp_keystore, capsys):
    assert init("foo:bar") == 0
    before = read(KeyManager(), "did:web:foo:bar")
    assert init("foo-bar") == 1
    assert read(KeyManager(), "did:web:foo:bar") == before


def test_add_post_quantum_key_flag(temp_keystore, capsys):
    args = types.SimpleNamespace(
        domain="agent.example.com", env=False, yes=True, add_post_quantum_key=True
    )
    assert cli.cmd_init(args) == 1  # nothing saved yet: nothing is created
    assert KeyManager().list_identities() == []

    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)
    assert cli.cmd_init(args) == 0
    upgraded = KeyManager().load_identity(DID)
    assert upgraded.private_key_jwk == old.private_key_jwk and pq(upgraded) is not None


def test_concurrent_first_runs_of_vouch_init_make_one_identity(tmp_path):
    import subprocess
    import sys

    script = (
        "import types, sys\n"
        "from vouch import cli\n"
        "sys.exit(cli.cmd_init(types.SimpleNamespace(domain='race.example.com', env=False, yes=True)))\n"
    )
    env = {**os.environ, "HOME": str(tmp_path), "PYTHONPATH": os.getcwd()}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(6)
    ]
    outs = [p.communicate(timeout=120)[0] for p in procs]
    assert all(p.returncode == 0 for p in procs)
    created = [o for o in outs if "NEW AGENT IDENTITY GENERATED" in o]
    assert len(created) == 1
    with open(tmp_path / ".vouch" / "keys" / "did-web-race.example.com.json") as f:
        on_disk = json.load(f)["public_key"]
    assert on_disk in created[0]


def test_sidecar_reports_a_damaged_identity(temp_keystore):
    init()
    _damage_row(KeyManager())
    with pytest.raises(sidecar.SidecarError, match="damaged"):
        sidecar.build_sidecar(parse())


def test_sidecar_hybrid_with_an_environment_key_explains_the_key_source(temp_keystore, monkeypatch):
    keys = generate_identity("agent.example.com")
    monkeypatch.setenv(sidecar.PRIVATE_KEY_ENV, keys.private_key_jwk)
    with pytest.raises(sidecar.SidecarError, match="environment"):
        sidecar.build_sidecar(parse("--did", DID, "--hybrid"))


def test_sidecar_on_a_read_only_keystore_says_what_failed(temp_keystore):
    KeyManager().save_identity(generate_identity("agent.example.com"))
    os.chmod(temp_keystore, 0o500)
    try:
        if os.access(temp_keystore, os.W_OK):
            pytest.skip("running as a user who can write anywhere")
        with pytest.raises(sidecar.SidecarError, match="post-quantum"):
            sidecar.build_sidecar(parse("--hybrid"))
    finally:
        os.chmod(temp_keystore, 0o700)


def test_wizard_reports_a_damaged_identity(temp_keystore, tmp_path, capsys):
    from vouch import onboard

    init()
    _damage_row(KeyManager())
    args = types.SimpleNamespace(
        quick=True, domain="agent.example.com", non_interactive=True, out_dir=str(tmp_path / "out")
    )
    os.makedirs(args.out_dir)
    assert onboard.cmd_onboard(args) == 2
    assert "damaged" in capsys.readouterr().err


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_wizard_publishes_the_saved_post_quantum_key(
    temp_keystore, tmp_path, monkeypatch, password
):
    from vouch import onboard

    monkeypatch.setattr(onboard, "STATE_PATH", tmp_path / "state.json")
    keys = generate_identity("agent.example.com", post_quantum=True)
    KeyManager().save_identity(keys, password)
    if password:
        monkeypatch.setenv("VOUCH_KEY_PASSPHRASE", password)
    out = tmp_path / "out"
    out.mkdir()
    args = types.SimpleNamespace(
        quick=True, domain="agent.example.com", non_interactive=True, out_dir=str(out)
    )

    assert onboard.cmd_onboard(args) == 0

    with open(out / "did.json") as f:
        doc = json.load(f)
    second = [m for m in doc["verificationMethod"] if m["id"] == f"{DID}#key-2"]
    assert second and second[0]["publicKeyMultibase"] == pq(keys).public_key
    assert f"{DID}#key-2" in doc["assertionMethod"]


def test_autosign_stops_on_a_damaged_identity(temp_keystore, monkeypatch, caplog):
    import vouch.autosign as autosign

    monkeypatch.setenv("VOUCH_AUTO_IDENTITY", "1")
    monkeypatch.delenv("VOUCH_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VOUCH_DID", raising=False)
    init()
    _damage_row(KeyManager())

    autosign.reset_default_signer()
    try:
        assert autosign.resolve_signer() is None  # no throwaway identity either
        assert "damaged" in caplog.text
    finally:
        autosign.reset_default_signer()


def test_autosign_uses_the_saved_key_for_an_environment_identity(temp_keystore, monkeypatch):
    import vouch.autosign as autosign

    keys = generate_identity("agent.example.com", post_quantum=True)
    KeyManager().save_identity(keys)
    monkeypatch.setenv("VOUCH_PRIVATE_KEY", keys.private_key_jwk)
    monkeypatch.setenv("VOUCH_DID", DID)

    autosign.reset_default_signer()
    try:
        signer = autosign.resolve_signer()
        assert signer.has_saved_mldsa44_key()
        assert signer.public_key_mldsa44_multikey() == pq(keys).public_key
    finally:
        autosign.reset_default_signer()


def test_vouch_init_works_without_the_post_quantum_package(temp_keystore, monkeypatch, capsys):
    from vouch import data_integrity_hybrid

    def missing():
        raise ImportError("Hybrid post-quantum cryptosuite requires the 'pqcrypto' package")

    monkeypatch.setattr(data_integrity_hybrid, "_import_pqcrypto", missing)
    assert init() == 0
    assert "pqcrypto" in capsys.readouterr().out
    assert pq(KeyManager().load_identity(DID)) is None


def test_a_two_key_identity_loads_without_the_post_quantum_package(km, monkeypatch):
    from vouch import data_integrity_hybrid

    keys = saved(km)

    def missing():
        raise ImportError("no pqcrypto")

    monkeypatch.setattr(data_integrity_hybrid, "_import_pqcrypto", missing)
    loaded = km.load_identity(DID)
    assert loaded.private_key_jwk == keys.private_key_jwk
    assert pq(loaded).public_key == pq(keys).public_key


# ---------------------------------------------------------------------------
# Third review round
# ---------------------------------------------------------------------------


def _quick_onboard(tmp_path, monkeypatch):
    from vouch import onboard

    monkeypatch.setattr(onboard, "STATE_PATH", tmp_path / "state.json")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    args = types.SimpleNamespace(
        quick=True, domain="agent.example.com", non_interactive=True, out_dir=str(out)
    )
    return onboard.cmd_onboard(args), out


def test_wizard_leaves_out_an_unchecked_key_of_a_locked_identity(
    temp_keystore, tmp_path, monkeypatch, capsys
):
    monkeypatch.delenv("VOUCH_KEY_PASSPHRASE", raising=False)
    keys = generate_identity("agent.example.com", post_quantum=True)
    KeyManager().save_identity(keys, PASSWORD)
    # Someone who cannot unlock the file swaps in a public key of their own.
    data = read(KeyManager())
    data["keys"][0]["public_key"] = new_post_quantum_key().public_key
    write(KeyManager(), data)

    rc, out = _quick_onboard(tmp_path, monkeypatch)
    assert rc == 0
    with open(out / "did.json") as f:
        ids = [m["id"] for m in json.load(f)["verificationMethod"]]
    assert ids == [f"{DID}#key-1"]
    assert "left out" in capsys.readouterr().out

    monkeypatch.setenv("VOUCH_KEY_PASSPHRASE", PASSWORD)
    rc, _ = _quick_onboard(tmp_path, monkeypatch)
    assert rc == 2 and "damaged" in capsys.readouterr().err


def test_autosign_stops_on_an_unreadable_identity_file(temp_keystore, monkeypatch):
    import vouch.autosign as autosign

    monkeypatch.setenv("VOUCH_AUTO_IDENTITY", "1")
    monkeypatch.delenv("VOUCH_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VOUCH_DID", raising=False)
    KeyManager().save_identity(generate_identity("other.example.com"))
    init()
    path = KeyManager()._get_filename(DID)
    with open(path) as f:
        cut = f.read()[:3000]
    with open(path, "w") as f:
        f.write(cut)

    autosign.reset_default_signer()
    try:
        assert autosign.resolve_signer() is None
    finally:
        autosign.reset_default_signer()


def _add(did=None, domain="agent.example.com"):
    return cli.cmd_init(
        types.SimpleNamespace(
            domain=None if did else domain, did=did, env=False, yes=True, add_post_quantum_key=True
        )
    )


def test_add_flag_on_a_locked_identity_needs_the_passphrase(temp_keystore, monkeypatch):
    monkeypatch.delenv("VOUCH_KEY_PASSPHRASE", raising=False)
    KeyManager().save_identity(generate_identity("agent.example.com"), PASSWORD)

    assert _add() == 1
    assert "keys" not in read(KeyManager())

    monkeypatch.setenv("VOUCH_KEY_PASSPHRASE", PASSWORD)
    assert _add() == 0
    assert pq(KeyManager().load_identity(DID, PASSWORD)) is not None


def test_add_flag_works_for_any_did_method(temp_keystore):
    from vouch.root_of_trust import generate_did_key_identity

    keys = generate_did_key_identity()
    KeyManager().save_identity(keys)
    assert _add(did=keys.did) == 0
    loaded = KeyManager().load_identity(keys.did)
    assert loaded.private_key_jwk == keys.private_key_jwk and pq(loaded) is not None
    assert _add(did="did:key:z6MkNothingSavedHere") == 1


def test_did_without_the_add_flag_is_refused(temp_keystore):
    args = types.SimpleNamespace(
        domain=None, did=DID, env=False, yes=True, add_post_quantum_key=False
    )
    assert cli.cmd_init(args) == 1
    assert KeyManager().list_identities() == []


def test_keep_path_refuses_a_file_of_another_did(temp_keystore, capsys):
    assert init("a:b") == 0
    before = read(KeyManager(), "did:web:a:b")
    assert cli._keep_existing_identity("did:web:a-b", types.SimpleNamespace(yes=True)) == 1
    assert read(KeyManager(), "did:web:a:b") == before


def test_sidecar_key_file_advice_names_the_identity(temp_keystore, tmp_path):
    old = generate_identity("agent.example.com")
    KeyManager().save_identity(old)
    with pytest.raises(sidecar.SidecarError, match=f"--did {DID}"):
        sidecar.build_sidecar(parse("--key", KeyManager()._get_filename(DID), "--hybrid"))


def test_without_the_post_quantum_package(temp_keystore, monkeypatch, capsys):
    from vouch import data_integrity_hybrid

    init()

    def missing():
        raise ImportError("no pqcrypto")

    monkeypatch.setattr(data_integrity_hybrid, "_import_pqcrypto", missing)
    with pytest.raises(sidecar.SidecarError, match="pqcrypto"):
        sidecar.build_sidecar(parse("--hybrid"))
    assert sidecar.build_sidecar(parse()).config.post_quantum == "saved"

    old = generate_identity("old.example.com")
    KeyManager().save_identity(old)
    with pytest.raises(sidecar.SidecarError, match="pqcrypto"):
        sidecar.build_sidecar(parse("--did", old.did, "--hybrid"))
    assert init("old.example.com") == 0  # a plain rerun still succeeds


def test_adding_a_key_is_logged(km, caplog):
    saved(km, post_quantum=False)
    with caplog.at_level("WARNING", logger="vouch.keys"):
        km.ensure_post_quantum_key(DID)
    assert "Added a post-quantum key" in caplog.text


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(v=True),
        lambda d: d.update(v=1.0),
        lambda d: d.update(v="1"),
    ],
    ids=["v true", "v 1.0", "v string"],
)
def test_a_one_key_file_must_say_version_one_exactly(km, change):
    saved(km, post_quantum=False)
    data = read(km)
    change(data)
    write(km, data)
    with pytest.raises(IdentityDamagedError):
        km.load_identity(DID)


def test_non_canonical_base64_and_nan_are_refused(km):
    saved(km)
    data = read(km)
    encoded = data["keys"][0]["private_key"]
    # Change the padding bits of the last character without changing the bytes.
    last = encoded.rstrip("=")[-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    sibling = alphabet[alphabet.index(last) ^ 1]
    tail = len(encoded) - len(encoded.rstrip("="))
    data["keys"][0]["private_key"] = encoded.rstrip("=")[:-1] + sibling + "=" * tail
    write(km, data)
    with pytest.raises(IdentityDamagedError):
        km.load_identity(DID)

    saved(km)
    with open(km._get_filename(DID)) as f:
        text = f.read()
    with open(km._get_filename(DID), "w") as f:
        f.write(text.replace('"v": 2', '"v": 2, "extra": NaN'))
    with pytest.raises(IdentityDamagedError):
        km.load_identity(DID)


def test_upgrade_call_sweeps_old_temporary_files(km):
    saved(km)
    old = km._get_filename(DID) + ".9.dead.tmp"
    with open(old, "w") as f:
        f.write("{}")
    os.utime(old, (1, 1))
    km.ensure_post_quantum_key(DID)
    assert not os.path.exists(old)


# ---------------------------------------------------------------------------
# Fourth review round
# ---------------------------------------------------------------------------


def test_autosign_without_a_writable_home_still_falls_back(monkeypatch, tmp_path):
    import vouch.autosign as autosign

    def unusable(self, key_dir=None):
        raise PermissionError(13, "Permission denied", "/nonexistent")

    monkeypatch.setattr(KeyManager, "__init__", unusable)
    monkeypatch.setenv("VOUCH_AUTO_IDENTITY", "1")
    monkeypatch.delenv("VOUCH_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VOUCH_DID", raising=False)
    autosign.reset_default_signer()
    try:
        signer = autosign.resolve_signer()
        assert signer is not None and signer.get_did() == "did:web:ephemeral.agent.local"
    finally:
        autosign.reset_default_signer()


def test_an_exported_passphrase_does_not_break_unlocked_identities(
    temp_keystore, tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("VOUCH_KEY_PASSPHRASE", "for-another-identity")

    rc, out = _quick_onboard(tmp_path, monkeypatch)
    assert rc == 0
    with open(out / "did.json") as f:
        ids = [m["id"] for m in json.load(f)["verificationMethod"]]
    assert ids == [f"{DID}#key-1", f"{DID}#key-2"]

    assert init() == 0  # a plain rerun on the unlocked identity


def test_vouch_init_refuses_both_did_and_domain(temp_keystore):
    from vouch.root_of_trust import generate_did_key_identity

    keys = generate_did_key_identity()
    KeyManager().save_identity(keys)
    args = types.SimpleNamespace(
        domain="agent.example.com", did=keys.did, env=False, yes=True, add_post_quantum_key=True
    )
    assert cli.cmd_init(args) == 1
    assert pq(KeyManager().load_identity(keys.did)) is None


def test_sidecar_key_file_refuses_nan(temp_keystore, tmp_path):
    path = tmp_path / "identity.json"
    keys = generate_identity("agent.example.com")
    path.write_text(
        '{"id": "%s", "v": NaN, "private_key": %s}' % (DID, json.dumps(keys.private_key_jwk))
    )
    with pytest.raises(sidecar.SidecarError, match="not valid JSON"):
        sidecar.build_sidecar(parse("--key", str(path)))
