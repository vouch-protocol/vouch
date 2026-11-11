"""Evidence checks of the grader and the guarded fetcher behind them."""

import base64
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vouch import grade as g
from vouch import ssrf

VECTOR = json.loads(
    (Path(__file__).resolve().parent.parent / "test-vectors" / "grade" / "vector.json").read_text()
)
NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)


def _case(name):
    return next(c for c in VECTOR["cases"] if c["name"] == name)


@pytest.mark.parametrize("case", VECTOR["cases"], ids=[c["name"] for c in VECTOR["cases"]])
def test_shared_vector(case):
    got = g.evidence_signals(
        case["did"], case["didDocument"], case["cards"], case["documents"].get, NOW
    )
    assert got == case["expected"]


def test_vector_now_matches():
    assert VECTOR["now"] == "2026-11-11T00:00:00Z"


def test_status_list_expires_with_the_clock():
    case = _case("real-mldsa44-key")
    later = datetime(2036, 1, 1, tzinfo=timezone.utc)
    ok, why = g.revocation_signal(case["didDocument"], case["did"], case["documents"].get, later)
    assert not ok
    assert why.endswith("expired 2036-01-01T00:00:00Z")


def test_status_list_not_yet_valid():
    case = _case("real-mldsa44-key")
    early = datetime(2025, 12, 31, tzinfo=timezone.utc)
    ok, why = g.revocation_signal(case["didDocument"], case["did"], case["documents"].get, early)
    assert not ok
    assert "is not valid until 2026-01-01T00:00:00Z" in why


def test_tampered_status_list_fails():
    case = _case("real-mldsa44-key")
    url, lst = next(iter(case["documents"].items()))
    tampered = json.loads(json.dumps(lst))
    tampered["validUntil"] = "2099-01-01T00:00:00Z"
    ok, why = g.revocation_signal(case["didDocument"], case["did"], {url: tampered}.get, NOW)
    assert not ok
    assert "does not verify against #key-1" in why


def test_tampered_card_credential_is_declared_only():
    case = _case("real-mldsa44-key")
    card = json.loads(json.dumps(case["cards"][0]))
    card["vouchCredential"]["credentialSubject"]["intent"]["action"] = "anything"
    state, why = g.card_identity_signal(card, case["didDocument"], case["did"], NOW)
    assert state == "declared"
    assert "does not verify" in why


def test_card_credential_needs_the_did_document():
    case = _case("real-mldsa44-key")
    state, why = g.card_identity_signal(case["cards"][0], None, case["did"], NOW)
    assert state == "declared"
    assert "without a DID document" in why


def test_proof_set_requires_every_eddsa_proof():
    case = _case("real-mldsa44-key")
    url, lst = next(iter(case["documents"].items()))
    good = lst["proof"]
    bad = dict(good, proofValue="z" + "1" * 86)
    for proofs in ([good, bad], [bad, good]):
        doc = dict(lst, proof=proofs)
        ok, _ = g.revocation_signal(case["didDocument"], case["did"], {url: doc}.get, NOW)
        assert not ok
    ok, _ = g.revocation_signal(
        case["didDocument"], case["did"], {url: dict(lst, proof=[good])}.get, NOW
    )
    assert ok


def test_mldsa_text_in_ids_does_not_count():
    doc = {
        "id": "did:web:x.example",
        "verificationMethod": [
            {
                "id": "did:web:x.example#ml-dsa-44",
                "type": "Multikey",
                "controller": "did:web:x.example",
                "publicKeyMultibase": "zMLDSAdilithium",
            }
        ],
        "assertionMethod": ["did:web:x.example#ml-dsa-44"],
    }
    assert g.post_quantum_signal(doc, "did:web:x.example") == (
        False,
        "no ML-DSA-44 verification method",
    )


def test_encoded_list_rejects_oversized_expansion():
    bomb = gzip.compress(bytes(g.STATUS_LIST_MAX_DECODED_BYTES + 1024), mtime=0)
    encoded = "u" + base64.urlsafe_b64encode(bomb).rstrip(b"=").decode()
    assert not g._encoded_list_decodes(encoded)


def test_encoded_list_rejects_bad_alphabet_and_truncation():
    ok = "u" + base64.urlsafe_b64encode(gzip.compress(bytes(16384), mtime=0)).rstrip(b"=").decode()
    assert g._encoded_list_decodes(ok)
    assert not g._encoded_list_decodes("z" + ok[1:])
    assert not g._encoded_list_decodes(ok + "!")
    assert not g._encoded_list_decodes(ok[:-12])


def test_inspect_domain_uses_injected_fetch_and_keeps_the_score():
    case = _case("real-mldsa44-key")
    docs = {
        "https://grade.example/.well-known/did.json": case["didDocument"],
        "https://grade.example/.well-known/agent-card.json": case["cards"][0],
        **case["documents"],
    }
    report = g.grade_domain("grade.example", fetch=docs.get, now=NOW)
    assert report.score == 100 and report.grade == "A"
    assert report.signals["pq_ready"] and report.signals["has_revocation"]
    assert report.signals["card_identity"] == "verified"
    assert report.signals["has_card_identity"] is True
    assert report.fixes == []


def test_missing_did_document_explains_every_signal():
    report = g.grade_domain("grade.example", fetch={}.get, now=NOW)
    assert report.score == 0
    assert report.signals["reasons"] == {
        "pq_ready": "no DID document",
        "has_revocation": "no DID document",
        "card_identity": "no agent card",
    }
    assert any("Found: no DID document." in f for f in report.fixes)


# ---------------------------------------------------------------------------
# Guarded fetcher
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self._body = body
        self._headers = headers or {}

    def getheader(self, name):
        return self._headers.get(name)

    def read(self, n):
        chunk, self._body = self._body[:n], self._body[n:]
        return chunk


class _FakeNet:
    """Stands in for DNS and the pinned connection."""

    def __init__(self, dns, routes):
        self.dns = dns
        self.routes = routes
        self.connected = []

    def install(self, monkeypatch):
        net = self

        def resolve(host, port):
            return net.dns.get(host, [host])

        class Conn:
            def __init__(self, host, port, ip, timeout):
                self.host, self.ip = host, ip

            def request(self, method, path, headers=None):
                net.connected.append((self.host, self.ip, path))
                self.key = f"https://{self.host}{path}"

            def getresponse(self):
                return net.routes[self.key]

            def close(self):
                pass

        monkeypatch.setattr(ssrf, "_resolved_ips", resolve)
        monkeypatch.setattr(ssrf, "_PinnedHTTPSConnection", Conn)


def test_fetch_json_pins_the_validated_address(monkeypatch):
    net = _FakeNet(
        {"a.example": ["93.184.216.34"]},
        {"https://a.example/x.json": _Resp(200, b'{"ok": true}')},
    )
    net.install(monkeypatch)
    assert ssrf.fetch_json("https://a.example/x.json") == {"ok": True}
    assert net.connected == [("a.example", "93.184.216.34", "/x.json")]


def test_fetch_refuses_http_and_private_hosts(monkeypatch):
    net = _FakeNet({"inside.example": ["10.0.0.7"]}, {})
    net.install(monkeypatch)
    with pytest.raises(ssrf.SSRFError):
        ssrf.fetch_json("http://a.example/x.json")
    with pytest.raises(ssrf.SSRFError):
        ssrf.fetch_json("https://inside.example/x.json")
    with pytest.raises(ssrf.SSRFError):
        ssrf.fetch_json("https://169.254.169.254/latest/meta-data")
    assert net.connected == []


def test_redirect_to_a_private_address_is_refused(monkeypatch):
    net = _FakeNet(
        {"a.example": ["93.184.216.34"], "inside.example": ["192.168.1.5"]},
        {
            "https://a.example/x.json": _Resp(
                302, headers={"Location": "https://inside.example/secret"}
            )
        },
    )
    net.install(monkeypatch)
    with pytest.raises(ssrf.SSRFError):
        ssrf.fetch_json("https://a.example/x.json")
    assert [c[0] for c in net.connected] == ["a.example"]


def test_redirect_to_http_is_refused(monkeypatch):
    net = _FakeNet(
        {"a.example": ["93.184.216.34"]},
        {"https://a.example/x.json": _Resp(301, headers={"Location": "http://a.example/x.json"})},
    )
    net.install(monkeypatch)
    with pytest.raises(ssrf.SSRFError):
        ssrf.fetch_json("https://a.example/x.json")


def test_redirects_are_followed_and_capped(monkeypatch):
    routes = {
        f"https://a.example/{i}": _Resp(302, headers={"Location": f"/{i + 1}"}) for i in range(5)
    }
    routes["https://a.example/5"] = _Resp(200, b"[1]")
    net = _FakeNet({"a.example": ["93.184.216.34"]}, routes)
    net.install(monkeypatch)
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/0", max_redirects=3)
    net.routes = {
        "https://a.example/0": _Resp(302, headers={"Location": "/1"}),
        "https://a.example/1": _Resp(200, b"[1]"),
    }
    assert ssrf.fetch_json("https://a.example/0", max_redirects=3) == [1]
    net.routes = {"https://a.example/0": _Resp(302, headers={"Location": "/1"})}
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/0", max_redirects=0)


def test_size_limit_applies_to_declared_and_actual_length(monkeypatch):
    net = _FakeNet(
        {"a.example": ["93.184.216.34"]},
        {
            "https://a.example/declared": _Resp(200, b"{}", headers={"Content-Length": "999999"}),
            "https://a.example/actual": _Resp(200, b"[" + b"0," * 600 + b"0]"),
        },
    )
    net.install(monkeypatch)
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/declared", max_bytes=1000)
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/actual", max_bytes=1000)


def test_non_200_and_non_json_are_fetch_errors(monkeypatch):
    net = _FakeNet(
        {"a.example": ["93.184.216.34"]},
        {
            "https://a.example/missing": _Resp(404),
            "https://a.example/html": _Resp(200, b"<html></html>"),
        },
    )
    net.install(monkeypatch)
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/missing")
    with pytest.raises(ssrf.FetchError):
        ssrf.fetch_json("https://a.example/html")


def test_grader_treats_unsafe_fetches_as_missing(monkeypatch):
    net = _FakeNet({"grade.example": ["127.0.0.1"]}, {})
    net.install(monkeypatch)
    report = g.grade_domain("grade.example")
    assert report.score == 0
    assert net.connected == []


def test_only_the_first_status_list_services_are_fetched():
    case = _case("real-mldsa44-key")
    url, lst = next(iter(case["documents"].items()))
    doc = json.loads(json.dumps(case["didDocument"]))
    doc["service"] = [
        {
            "id": f"#s{i}",
            "type": "BitstringStatusList",
            "serviceEndpoint": f"https://n{i}.example/l",
        }
        for i in range(10)
    ] + doc["service"]
    asked = []

    def fetch(u):
        asked.append(u)
        return {url: lst}.get(u)

    ok, _ = g.revocation_signal(doc, case["did"], fetch, NOW)
    assert not ok
    assert len(asked) == g.STATUS_LIST_MAX_SERVICES
