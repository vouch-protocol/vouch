"""
Tests for the published JSON-LD context and vocabulary.

The context at https://vouch-protocol.com/contexts/v1 is named by every
credential the reference builders produce. These tests keep the three in step:
the context document, the vocabulary it points into, and the terms the builders
emit. They also guard the rules a context must follow to sit after the W3C
credentials v2 context without breaking it.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterator, Set, Tuple

import pytest

from vouch import root_of_trust, vc
from vouch.signer import Signer

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTEXT_PATH = REPO_ROOT / "website" / "public" / "contexts" / "v1.jsonld"
VOCAB_PATH = REPO_ROOT / "website" / "public" / "ns" / "v1.jsonld"

NAMESPACE = "https://vouch-protocol.com/ns/v1#"
ALLOWED_NAMESPACES = (
    NAMESPACE,
    "https://www.w3.org/2018/credentials#",
    "https://w3id.org/security#",
)
ALLOWED_COERCIONS = frozenset(
    {
        "@id",
        "http://www.w3.org/2001/XMLSchema#anyURI",
        "http://www.w3.org/2001/XMLSchema#dateTime",
        "http://www.w3.org/2001/XMLSchema#double",
        "http://www.w3.org/2001/XMLSchema#integer",
    }
)
TERM_KEYWORDS = frozenset({"@id", "@type", "@container", "@context"})

# Terms the W3C credentials v2 context protects: its top-level terms and the
# ones it scopes to a VerifiableCredential. A context listed after it must not
# define any of them at its own top level.
BASE_CONTEXT_TERMS = frozenset(
    {
        "...",
        "BitstringStatusList",
        "BitstringStatusListCredential",
        "BitstringStatusListEntry",
        "DataIntegrityProof",
        "EnvelopedVerifiableCredential",
        "EnvelopedVerifiablePresentation",
        "JsonSchema",
        "JsonSchemaCredential",
        "VerifiableCredential",
        "VerifiablePresentation",
        "_sd",
        "_sd_alg",
        "aud",
        "cnf",
        "confidenceMethod",
        "credentialSchema",
        "credentialStatus",
        "credentialSubject",
        "description",
        "digestMultibase",
        "digestSRI",
        "evidence",
        "exp",
        "iat",
        "iss",
        "issuer",
        "jku",
        "kid",
        "mediaType",
        "name",
        "nbf",
        "proof",
        "refreshService",
        "relatedResource",
        "renderMethod",
        "sub",
        "termsOfUse",
        "validFrom",
        "validUntil",
        "x5u",
    }
)


@pytest.fixture(scope="module")
def context() -> Dict[str, Any]:
    document = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))
    assert list(document.keys()) == ["@context"]
    return document["@context"]


@pytest.fixture(scope="module")
def vocabulary() -> Dict[str, Any]:
    return json.loads(VOCAB_PATH.read_text(encoding="utf-8"))


def _terms(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """The term definitions of one context object, without its keywords."""
    return {key: value for key, value in ctx.items() if not key.startswith("@")}


def _walk(ctx: Dict[str, Any], path: str = "") -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Yield every context object in the document: the top level and each scoped one."""
    yield path or "(top level)", ctx
    for name, definition in _terms(ctx).items():
        if isinstance(definition, dict) and "@context" in definition:
            yield from _walk(definition["@context"], f"{path}/{name}")


def _term_iri(definition: Any) -> str:
    return definition if isinstance(definition, str) else definition["@id"]


def _signer() -> Signer:
    return Signer.from_keypair(root_of_trust.generate_did_key_identity())


def test_context_file_is_published_where_the_builders_point():
    assert vc.VOUCH_CONTEXT_V1 == "https://vouch-protocol.com/contexts/v1"
    assert CONTEXT_PATH.name == "v1.jsonld" and CONTEXT_PATH.parent.name == "contexts"


def test_context_header(context):
    assert context["@version"] == 1.1
    assert context["@protected"] is True
    assert context["@vocab"] == NAMESPACE
    # Identical to the base context's aliases, which is the only redefinition
    # a protected term allows.
    assert context["id"] == "@id"
    assert context["type"] == "@type"


def test_every_scoped_context_is_protected(context):
    for path, ctx in _walk(context):
        assert ctx.get("@protected") is True, f"{path} is not protected"


def test_top_level_terms_do_not_redefine_the_base_context(context):
    clash = (set(_terms(context)) - {"id", "type"}) & BASE_CONTEXT_TERMS
    assert clash == set()


def test_term_definitions_are_absolute_and_well_formed(context):
    for path, ctx in _walk(context):
        for name, definition in _terms(ctx).items():
            where = f"{path}/{name}"
            if definition in ("@id", "@type"):
                continue
            iri = _term_iri(definition)
            assert iri.startswith(ALLOWED_NAMESPACES), f"{where} maps to {iri}"
            assert " " not in iri and iri.count("#") == 1, where
            if isinstance(definition, dict):
                assert set(definition) <= TERM_KEYWORDS, where
                if "@type" in definition:
                    assert definition["@type"] in ALLOWED_COERCIONS, where
                if "@container" in definition:
                    assert definition["@container"] in ("@list", "@graph"), where


def test_vouch_terms_are_named_after_their_json_key(context):
    """A term in the vocabulary namespace always maps to namespace + its own name."""
    for path, ctx in _walk(context):
        for name, definition in _terms(ctx).items():
            if definition in ("@id", "@type"):
                continue
            iri = _term_iri(definition)
            if iri.startswith(NAMESPACE):
                assert iri == NAMESPACE + name, f"{path}/{name} maps to {iri}"


def test_credential_types_of_the_reference_are_defined(context):
    for type_name in (
        vc.VOUCH_CREDENTIAL_TYPE,
        vc.SESSION_VOUCHER_TYPE,
        root_of_trust.ROOT_OF_TRUST_TYPE,
        root_of_trust.RECOGNIZED_ISSUER_TYPE,
        root_of_trust.AGENT_IDENTITY_TYPE,
    ):
        assert context.get(type_name) == NAMESPACE + type_name


def test_vouch_credential_uses_defined_terms(context):
    link = {
        "issuer": "did:web:alice.example.com",
        "subject": "did:web:agent.example.com",
        "intent": {
            "action": "plan_trip",
            "target": "destination:Paris",
            "resource": "https://travel.example/v1",
        },
        "validFrom": "2026-04-26T09:00:00Z",
        "validUntil": "2026-04-26T11:00:00Z",
        "proof": {"type": "DataIntegrityProof"},
    }
    credential = vc.build_vouch_credential(
        "did:web:agent.example.com",
        {
            "action": "read_database",
            "target": "users_table",
            "resource": "https://api.example.com/v1/users",
        },
        reputation_score=87,
        delegation_chain=[link],
    )
    assert credential["@context"] == [vc.VC_CONTEXT_V2, vc.VOUCH_CONTEXT_V1]
    subject = credential["credentialSubject"]
    for key in set(subject) - {"id"}:
        assert key in context, f"credentialSubject.{key} is not a defined term"

    intent_terms = _terms(context["intent"]["@context"])
    assert set(subject["intent"]) <= set(intent_terms)

    chain = context["delegationChain"]
    assert chain["@container"] == "@list", "a delegation chain is ordered"
    link_terms = set(_terms(chain["@context"])) | {"intent"}
    assert set(link) <= link_terms


def test_session_voucher_uses_defined_terms(context):
    voucher = vc.build_session_voucher(
        "did:key:z6MkAgent",
        ["did:web:validator-a"],
        decay_lambda=0.05,
        initial_trust=1.0,
        max_ttl_seconds=60,
        scope=["api:read"],
    )
    for key in set(voucher["credentialSubject"]) - {"id"}:
        assert key in context, f"credentialSubject.{key} is not a defined term"


def test_root_of_trust_credentials_use_defined_terms(context):
    root, issuer = _signer(), _signer()
    root_credential = root_of_trust.build_root_of_trust(root, name="Example Machine Identity Root")
    recognition = root_of_trust.build_recognized_issuer(root, issuer_did=issuer.did)
    identity = root_of_trust.build_agent_identity(
        issuer,
        subject_did=_signer().did,
        attributes={
            "owner": "Example Corp",
            "model": "example-model",
            "capabilityClass": "shopping",
        },
    )
    for credential in (root_credential, recognition, identity):
        for key in set(credential["credentialSubject"]) - {"id"}:
            assert key in context, f"credentialSubject.{key} is not a defined term"

    # "name" comes from the base context; "scope" is defined here.
    assert set(root_credential["credentialSubject"]["rootOfTrust"]) <= {"name", "scope"}
    assert "scope" in context
    assert context["recognizedIn"]["@type"] == "@id"
    identity_terms = set(_terms(context["identity"]["@context"]))
    assert set(identity["credentialSubject"]["identity"]) <= identity_terms


def _context_iris(context: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()
    for _path, ctx in _walk(context):
        for definition in _terms(ctx).values():
            if definition in ("@id", "@type"):
                continue
            iri = _term_iri(definition)
            if iri.startswith(NAMESPACE):
                found.add(iri)
    return found


def test_vocabulary_describes_exactly_the_terms_of_the_context(context, vocabulary):
    prefix = vocabulary["@context"]["vouch"]
    assert prefix == NAMESPACE
    described = set()
    for node in vocabulary["@graph"]:
        node_id = node["id"]
        if node_id.startswith("vouch:"):
            described.add(NAMESPACE + node_id[len("vouch:") :])
            assert node["type"] in ("rdfs:Class", "rdf:Property")
            assert node["label"] == node_id[len("vouch:") :]
            assert node["comment"].strip()
            assert node["isDefinedBy"] == NAMESPACE.rstrip("#")
    assert described == _context_iris(context)


def test_vocabulary_classes_are_the_credential_types(context, vocabulary):
    classes = {node["label"] for node in vocabulary["@graph"] if node.get("type") == "rdfs:Class"}
    assert classes == {
        vc.VOUCH_CREDENTIAL_TYPE,
        vc.SESSION_VOUCHER_TYPE,
        root_of_trust.ROOT_OF_TRUST_TYPE,
        root_of_trust.RECOGNIZED_ISSUER_TYPE,
        root_of_trust.AGENT_IDENTITY_TYPE,
    }
