"""
Generate the shared test vectors for the grader's evidence checks.

Each case gives a DID, its DID document, the documents a fetcher would return
by URL (status lists), the agent cards found, and the signals every
implementation must produce: `vouch.grade.evidence_signals` in Python and
`evidenceSignals` in agent-trust-index/grader-worker/evidence.js. The reasons
are part of the contract, so both implementations print the same text.

Keys are derived from fixed seeds so a re-run reproduces the Ed25519 material;
the ML-DSA-44 public key comes from a fresh keypair, so a re-run changes those
bytes and the vector must be regenerated as a whole.

Run from the repository root:

    python test-vectors/grade/generate.py
"""

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vouch import data_integrity, multikey
from vouch.data_integrity_hybrid import generate_mldsa44_keypair
from vouch.grade import evidence_signals
from vouch.status_list import StatusList

DID = "did:web:grade.example"
OTHER = "did:web:other.example"
NOW = "2026-11-11T00:00:00Z"
CREATED = datetime(2026, 1, 1, tzinfo=timezone.utc)
VALID_FROM = "2026-01-01T00:00:00Z"
VALID_UNTIL = "2036-01-01T00:00:00Z"
LIST_URL = "https://grade.example/credentials/status/1.json"
CARD_URL = "https://agent.grade.example/a2a"


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def _b64u(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


KEY1 = _key("vouch-protocol grade vector key-1")
STRANGER = _key("vouch-protocol grade vector stranger")
MLDSA_PUB, _MLDSA_PRIV = generate_mldsa44_keypair()


def _jwk_vm(fragment: str, key: Ed25519PrivateKey, controller: str = DID) -> dict:
    return {
        "id": f"{DID}#{fragment}",
        "type": "JsonWebKey2020",
        "controller": controller,
        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(_raw_pub(key))},
    }


def _mldsa_vm(fragment: str = "mldsa44-1", raw: bytes = MLDSA_PUB, controller: str = DID) -> dict:
    return {
        "id": f"{DID}#{fragment}",
        "type": "Multikey",
        "controller": controller,
        "publicKeyMultibase": "z" + multikey._b58encode(multikey.MLDSA44_PUB_PREFIX + raw),
    }


def _doc(vms, assertion, service=None) -> dict:
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": DID,
        "verificationMethod": vms,
        "authentication": [f"{DID}#key-1"],
        "assertionMethod": assertion,
    }
    if service is not None:
        doc["service"] = service
    return doc


SERVICE = [{"id": f"{DID}#revocation", "type": "BitstringStatusList", "serviceEndpoint": LIST_URL}]
BASE_DOC = _doc(
    [_jwk_vm("key-1", KEY1), _mldsa_vm()],
    [f"{DID}#key-1", f"{DID}#mldsa44-1"],
    SERVICE,
)


def _sign(cred: dict, key: Ed25519PrivateKey, vm: str) -> dict:
    signed = copy.deepcopy(cred)
    signed.pop("proof", None)
    signed["proof"] = data_integrity.build_proof(signed, key, vm, created=CREATED)
    return signed


def _status_list(
    issuer: str = DID,
    valid_until: str = VALID_UNTIL,
    key: Ed25519PrivateKey = KEY1,
    vm: str = f"{DID}#key-1",
    encoded: str = "",
) -> dict:
    lst = StatusList(status_list_id=LIST_URL, status_purpose="revocation")
    cred = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": LIST_URL,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer,
        "validFrom": VALID_FROM,
        "validUntil": valid_until,
        "credentialSubject": {
            "id": LIST_URL + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encoded or lst.encode(),
        },
    }
    return _sign(cred, key, vm)


def _card_credential(
    issuer: str = DID,
    target: str = CARD_URL,
    key: Ed25519PrivateKey = KEY1,
    vm: str = f"{DID}#key-1",
) -> dict:
    cred = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://vouch-protocol.com/contexts/v1",
        ],
        "id": "urn:uuid:5d3f1a2e-7c4b-4e0a-9b1d-2f6a8c0e4d71",
        "type": ["VerifiableCredential", "VouchCredential"],
        "issuer": issuer,
        "validFrom": VALID_FROM,
        "validUntil": VALID_UNTIL,
        "credentialSubject": {
            "id": issuer,
            "vouchVersion": "1.0",
            "intent": {"action": "operate", "target": target, "resource": "a2a:agent-card"},
        },
    }
    return _sign(cred, key, vm)


def _card(credential=None, **extra) -> dict:
    card = {
        "name": "Grade Example Agent",
        "description": "An agent used by the grader vectors.",
        "url": CARD_URL,
        "version": "1.0.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "qa", "name": "Q&A", "description": "Answers questions."}],
    }
    card.update(extra)
    if credential is not None:
        card["vouchCredential"] = credential
    return card


def _case(name, description, doc=None, documents=None, cards=None) -> dict:
    return {
        "name": name,
        "description": description,
        "did": DID,
        "didDocument": BASE_DOC if doc is None else doc,
        "documents": {LIST_URL: _status_list()} if documents is None else documents,
        "cards": [] if cards is None else cards,
    }


def _short_list() -> str:
    import base64
    import gzip

    return "u" + base64.urlsafe_b64encode(gzip.compress(bytes(1024), mtime=0)).rstrip(b"=").decode()


def cases() -> list:
    jwk_mldsa = {
        "id": f"{DID}#mldsa44-jwk",
        "type": "JsonWebKey",
        "controller": DID,
        "publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-44", "pub": _b64u(MLDSA_PUB)},
    }
    no_mldsa_doc = _doc(
        [
            dict(_jwk_vm("mldsa-ready", KEY1), id=f"{DID}#key-1"),
            {
                "id": f"{DID}#pq-note",
                "type": "JsonWebKey2020",
                "controller": DID,
                "description": "ML-DSA / mldsa / dilithium support planned",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(_raw_pub(KEY1))},
            },
        ],
        [f"{DID}#key-1"],
        SERVICE,
    )
    return [
        _case(
            "real-mldsa44-key",
            "A well-formed ML-DSA-44 Multikey in assertionMethod, a valid status list, "
            "and a valid signed card.",
            cards=[_card(_card_credential())],
        ),
        _case(
            "mldsa-text-without-key",
            "ML-DSA words in descriptions, no ML-DSA key.",
            doc=no_mldsa_doc,
        ),
        _case(
            "mldsa-not-in-assertion-method",
            "A well-formed ML-DSA-44 key that is listed only under authentication.",
            doc=_doc(
                [_jwk_vm("key-1", KEY1), _mldsa_vm()],
                [f"{DID}#key-1"],
                SERVICE,
            ),
        ),
        _case(
            "mldsa-truncated-key",
            "An ML-DSA-44 Multikey one byte short.",
            doc=_doc(
                [_jwk_vm("key-1", KEY1), _mldsa_vm(raw=MLDSA_PUB[:-1])],
                [f"{DID}#key-1", f"{DID}#mldsa44-1"],
                SERVICE,
            ),
        ),
        _case(
            "mldsa-other-controller",
            "A well-formed ML-DSA-44 key controlled by another DID.",
            doc=_doc(
                [_jwk_vm("key-1", KEY1), _mldsa_vm(controller=OTHER)],
                [f"{DID}#key-1", f"{DID}#mldsa44-1"],
                SERVICE,
            ),
        ),
        _case(
            "mldsa-jwk-akp",
            "A well-formed ML-DSA-44 JWK (kty AKP) referenced by a relative id.",
            doc=_doc(
                [_jwk_vm("key-1", KEY1), jwk_mldsa],
                ["#key-1", "#mldsa44-jwk"],
                SERVICE,
            ),
        ),
        _case(
            "unrelated-service-type",
            "The only service is a LinkedDomains entry.",
            doc=_doc(
                [_jwk_vm("key-1", KEY1), _mldsa_vm()],
                [f"{DID}#key-1", f"{DID}#mldsa44-1"],
                [
                    {
                        "id": f"{DID}#site",
                        "type": "LinkedDomains",
                        "serviceEndpoint": "https://grade.example",
                    }
                ],
            ),
        ),
        _case(
            "no-service",
            "No service entries at all.",
            doc=_doc([_jwk_vm("key-1", KEY1)], ["#key-1"]),
        ),
        _case(
            "status-list-expired",
            "The status list's validUntil is before now.",
            documents={LIST_URL: _status_list(valid_until="2026-06-01T00:00:00Z")},
        ),
        _case(
            "status-list-key-not-in-document",
            "The status list is signed by a key the DID document does not list.",
            documents={LIST_URL: _status_list(key=STRANGER, vm=f"{DID}#key-9")},
        ),
        _case(
            "status-list-wrong-signature",
            "The status list names #key-1 but is signed by another key.",
            documents={LIST_URL: _status_list(key=STRANGER)},
        ),
        _case(
            "status-list-other-issuer",
            "The status list is issued by another DID.",
            documents={LIST_URL: _status_list(issuer=OTHER, key=STRANGER, vm=f"{OTHER}#key-1")},
        ),
        _case(
            "status-list-short-bitstring",
            "The encodedList decodes to fewer than 131,072 bits.",
            documents={LIST_URL: _status_list(encoded=_short_list())},
        ),
        _case(
            "status-list-unfetchable",
            "The status list URL returns nothing.",
            documents={},
        ),
        _case(
            "card-unsigned",
            "An agent card with no DID and no credential.",
            cards=[_card()],
        ),
        _case(
            "card-names-did-only",
            "An agent card that names the DID but carries no credential.",
            cards=[_card(provider={"organization": "Grade Example", "did": DID})],
        ),
        _case(
            "card-signed-by-stranger",
            "A card credential that names #key-1 but is signed by another key.",
            cards=[_card(_card_credential(key=STRANGER))],
        ),
        _case(
            "card-bound-to-other-url",
            "A valid credential copied from a card with another url.",
            cards=[_card(_card_credential(target="https://elsewhere.example/a2a"))],
        ),
        _case(
            "card-best-of-two",
            "Two cards: an unsigned one and a signed one; the signed one counts.",
            cards=[_card(), _card(_card_credential())],
        ),
    ]


def main() -> None:
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    out = []
    for case in cases():
        documents = case["documents"]
        signals = evidence_signals(
            case["did"], case["didDocument"], case["cards"], documents.get, now
        )
        case["expected"] = signals
        out.append(case)
    vector = {
        "description": "Evidence checks of the grader: post-quantum key, revocation "
        "status list and agent-card identity. Fetches are replaced by the documents map.",
        "now": NOW,
        "cases": out,
    }
    path = Path(__file__).with_name("vector.json")
    path.write_text(json.dumps(vector, indent=2) + "\n")
    for case in out:
        e = case["expected"]
        print(
            f"{case['name']:34} pq={e['pq_ready']!s:5} rev={e['has_revocation']!s:5} "
            f"card={e['card_identity']:8} | {e['reasons']['pq_ready']} | "
            f"{e['reasons']['has_revocation']} | {e['reasons']['card_identity']}"
        )


if __name__ == "__main__":
    main()
