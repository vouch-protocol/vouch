"""Tests for executable caveats in delegation chains."""

import pytest

from vouch import Signer, generate_identity
from vouch.caveats import (
    REASON_BROKEN_CHAIN,
    REASON_BUDGET_EXCEEDED,
    REASON_INVALID_LINK_PROOF,
    REASON_UNKNOWN_TYPE,
    REASON_UNROOTED,
    CaveatError,
    allowlist,
    build_capability,
    caveat,
    chain_caveats,
    evaluate_caveat,
    flag_true,
    incident_gate,
    rate_limit,
    running_total_ceiling,
    time_window,
    value_ceiling,
    verify_capability,
)


def _id(domain):
    kp = generate_identity(domain=domain)
    return kp, Signer(private_key=kp.private_key_jwk, did=kp.did)


class TestEvaluateCaveat:
    def test_value_ceiling(self):
        c = value_ceiling("c", field="amount", limit=200)
        assert evaluate_caveat(c, {"amount": 200}) == (True, None)
        assert evaluate_caveat(c, {"amount": 201})[0] is False

    def test_running_total_ceiling(self):
        c = running_total_ceiling("c", limit=1000)
        assert evaluate_caveat(c, {"amount": 100, "runningTotal": 800}) == (True, None)
        assert evaluate_caveat(c, {"amount": 300, "runningTotal": 800})[0] is False

    def test_time_window(self):
        c = time_window("c", start=9, end=17)
        assert evaluate_caveat(c, {"hour": 9})[0] is True
        assert evaluate_caveat(c, {"hour": 17})[0] is False
        assert evaluate_caveat(c, {"hour": 8})[0] is False

    def test_allowlist(self):
        c = allowlist("c", field="region", values=["eu", "us"])
        assert evaluate_caveat(c, {"region": "eu"})[0] is True
        assert evaluate_caveat(c, {"region": "apac"})[0] is False

    def test_flag_and_incident(self):
        assert evaluate_caveat(flag_true("c", field="shipped"), {"shipped": True})[0] is True
        assert evaluate_caveat(flag_true("c", field="shipped"), {"shipped": False})[0] is False
        assert evaluate_caveat(incident_gate("c"), {"incidentActive": True})[0] is True
        assert evaluate_caveat(incident_gate("c"), {})[0] is False

    def test_rate_limit(self):
        c = rate_limit("c", max_count=3)
        assert evaluate_caveat(c, {"recentCount": 2})[0] is True
        assert evaluate_caveat(c, {"recentCount": 3})[0] is False

    def test_unknown_type_denies(self):
        allow, reason = evaluate_caveat({"id": "x", "type": "does_not_exist", "params": {}}, {})
        assert allow is False and reason == REASON_UNKNOWN_TYPE

    def test_deterministic(self):
        c = value_ceiling("c", limit=10)
        ctx = {"amount": 5}
        assert evaluate_caveat(c, ctx) == evaluate_caveat(c, ctx)

    def test_caveat_builder_validates(self):
        with pytest.raises(CaveatError):
            caveat("", "value_ceiling")


class TestChainAndAccumulation:
    def _chain(self):
        skp, store = _id("store.example.com")
        mkp, mgr = _id("manager.example.com")
        akp, agent = _id("agent.example.com")
        link1 = build_capability(
            store,
            to=mgr.get_did(),
            attenuation={"action": "refund"},
            caveats=[flag_true("shipped-only", field="shipped")],
        )
        link2 = build_capability(
            mgr,
            to=agent.get_did(),
            attenuation={"action": "refund", "resource": "usd:<=200"},
            caveats=[value_ceiling("under-200", field="amount", limit=200)],
            parent=link1,
        )
        keys = {
            store.get_did(): skp.public_key_jwk,
            mgr.get_did(): mkp.public_key_jwk,
            agent.get_did(): akp.public_key_jwk,
        }
        return [link1, link2], keys, store.get_did()

    def test_accumulates_both_caveats(self):
        chain, _, _ = self._chain()
        assert [c["id"] for c in chain_caveats(chain)] == ["shipped-only", "under-200"]

    def test_all_caveats_satisfied_allows(self):
        chain, keys, root = self._chain()
        assert (
            verify_capability(chain, keys.get, {"shipped": True, "amount": 120}, root_issuer=root)
            is None
        )

    def test_ancestor_caveat_binds_descendant(self):
        chain, keys, root = self._chain()
        # 'shipped-only' came from the STORE (root); it still blocks the agent.
        r = verify_capability(chain, keys.get, {"shipped": False, "amount": 120}, root_issuer=root)
        assert r == "caveat_denied:shipped-only"

    def test_own_caveat_blocks(self):
        chain, keys, root = self._chain()
        r = verify_capability(chain, keys.get, {"shipped": True, "amount": 5000}, root_issuer=root)
        assert r == "caveat_denied:under-200"

    def test_non_removal_via_root_check(self):
        chain, keys, root = self._chain()
        # Present only the leaf link, hoping 'shipped-only' vanishes.
        r = verify_capability(
            [chain[1]], keys.get, {"shipped": False, "amount": 120}, root_issuer=root
        )
        assert r == REASON_UNROOTED

    def test_broken_parent_linkage(self):
        # Two validly-signed links whose parent pointer does not match the
        # predecessor actually presented: linkage is broken though both proofs pass.
        skp, store = _id("store.example.com")
        mkp, mgr = _id("manager.example.com")
        akp, agent = _id("agent.example.com")
        real_parent = build_capability(store, to=mgr.get_did(), attenuation={"action": "refund"})
        other_parent = build_capability(store, to=mgr.get_did(), attenuation={"action": "read"})
        leaf = build_capability(
            mgr, to=agent.get_did(), attenuation={"action": "refund"}, parent=real_parent
        )
        keys = {store.get_did(): skp.public_key_jwk, mgr.get_did(): mkp.public_key_jwk}
        # Present other_parent (valid) in place of real_parent: leaf.parent.digest mismatches.
        r = verify_capability([other_parent, leaf], keys.get, {}, root_issuer=store.get_did())
        assert r == REASON_BROKEN_CHAIN

    def test_wrong_key_fails_link_proof(self):
        chain, keys, root = self._chain()
        bad = dict(keys)
        # point the store's DID at a different key
        okp, _ = _id("other.example.com")
        bad[chain[0]["issuer"]] = okp.public_key_jwk
        r = verify_capability(chain, bad.get, {"shipped": True, "amount": 120}, root_issuer=root)
        assert r == REASON_INVALID_LINK_PROOF

    def test_budget_exceeded(self):
        chain, keys, root = self._chain()
        r = verify_capability(
            chain, keys.get, {"shipped": True, "amount": 120}, root_issuer=root, max_caveats=1
        )
        assert r == REASON_BUDGET_EXCEEDED

    def test_empty_chain_rejected(self):
        with pytest.raises(CaveatError):
            verify_capability([], {}.get, {})


# ---------------------------------------------------------------------------
# Linkage, narrowing, expiry, and revocation of capability links
# ---------------------------------------------------------------------------


class TestLinkSecurity:
    def _parties(self):
        skp, store = _id("store.example.com")
        mkp, mgr = _id("manager.example.com")
        xkp, stranger = _id("stranger.example.com")
        akp, agent = _id("agent.example.com")
        keys = {
            store.get_did(): skp.public_key_jwk,
            mgr.get_did(): mkp.public_key_jwk,
            stranger.get_did(): xkp.public_key_jwk,
            agent.get_did(): akp.public_key_jwk,
        }
        return store, mgr, stranger, agent, keys

    def _root(self, store, mgr, **kw):
        return build_capability(
            store,
            to=mgr.get_did(),
            attenuation={"action": "refund"},
            caveats=[value_ceiling("cap", limit=200)],
            **kw,
        )

    def test_only_the_named_delegatee_can_issue_the_next_link(self):
        """The probe: a stranger (not the delegatee) issues a widened child."""
        from vouch.caveats import REASON_NOT_DELEGATEE

        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr)
        child = build_capability(
            stranger, to=agent.get_did(), attenuation={"action": "*"}, parent=root
        )
        r = verify_capability([root, child], keys.get, {"amount": 100}, root_issuer=store.get_did())
        assert r == REASON_NOT_DELEGATEE

    def test_child_attenuation_cannot_widen_parent(self):
        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr)
        child = build_capability(mgr, to=agent.get_did(), attenuation={"action": "*"}, parent=root)
        r = verify_capability([root, child], keys.get, {"amount": 100}, root_issuer=store.get_did())
        assert r == "scope_exceeds_parent:action"

    def test_links_carry_expiry(self):
        store, mgr, *_ = self._parties()
        root = self._root(store, mgr, valid_seconds=600)
        assert "validFrom" in root and "validUntil" in root

    def test_expired_link_fails(self):
        from datetime import datetime, timedelta, timezone

        from vouch.caveats import REASON_EXPIRED

        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr, valid_seconds=60)
        later = datetime.now(timezone.utc) + timedelta(hours=2)
        r = verify_capability(
            [root], keys.get, {"amount": 10}, root_issuer=store.get_did(), now=later
        )
        assert r == REASON_EXPIRED

    def test_link_without_expiry_fails(self):
        from vouch.caveats import REASON_MALFORMED_LINK, _attach_proof

        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr)
        undated = {k: v for k, v in root.items() if k not in ("proof", "validUntil")}
        undated = _attach_proof(undated, store)
        r = verify_capability([undated], keys.get, {"amount": 10}, root_issuer=store.get_did())
        assert r == REASON_MALFORMED_LINK

    def test_child_cannot_outlive_parent(self):
        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr, valid_seconds=60)
        child = build_capability(
            mgr,
            to=agent.get_did(),
            attenuation={"action": "refund"},
            parent=root,
            valid_seconds=86400,
        )
        # The builder clamps the child to its parent's window ...
        assert child["validUntil"] <= root["validUntil"]
        assert (
            verify_capability([root, child], keys.get, {"amount": 10}, root_issuer=store.get_did())
            is None
        )

    def test_revoked_link_or_issuer_fails(self):
        from vouch.caveats import REASON_REVOKED

        store, mgr, stranger, agent, keys = self._parties()
        root = self._root(store, mgr)
        child = build_capability(
            mgr, to=agent.get_did(), attenuation={"action": "refund"}, parent=root
        )
        chain = [root, child]
        ctx = {"amount": 10}
        assert verify_capability(chain, keys.get, ctx, root_issuer=store.get_did()) is None
        assert (
            verify_capability(
                chain, keys.get, ctx, root_issuer=store.get_did(), revoked={root["id"]}
            )
            == REASON_REVOKED
        )
        assert (
            verify_capability(
                chain,
                keys.get,
                ctx,
                root_issuer=store.get_did(),
                revoked=lambda i: i == mgr.get_did(),
            )
            == REASON_REVOKED
        )
