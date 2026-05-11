"""
Unit tests for the W3C BitstringStatusList implementation (W3C CG Report §11.2).
"""

import base64
import gzip

import pytest

from vouch.status_list import (
    BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
    BITSTRING_STATUS_LIST_ENTRY_TYPE,
    BITSTRING_STATUS_LIST_SUBJECT_TYPE,
    DEFAULT_BITSTRING_LENGTH,
    MULTIBASE_BASE64URL_PREFIX,
    STATUS_PURPOSE_REVOCATION,
    STATUS_PURPOSE_SUSPENSION,
    StatusList,
    StatusListError,
    build_status_list_credential,
    build_status_list_entry,
    verify_status,
)
from vouch.vc import build_vouch_credential


STATUS_URL = "https://issuer.example/status/3"


class TestStatusListConstruction:
    def test_default_length_and_purpose(self):
        sl = StatusList(status_list_id=STATUS_URL)
        assert sl.length == DEFAULT_BITSTRING_LENGTH
        assert sl.status_purpose == STATUS_PURPOSE_REVOCATION

    def test_rejects_short_bitstring(self):
        with pytest.raises(StatusListError):
            StatusList(status_list_id=STATUS_URL, length=1024)

    def test_rejects_non_multiple_of_eight(self):
        with pytest.raises(StatusListError):
            StatusList(status_list_id=STATUS_URL, length=DEFAULT_BITSTRING_LENGTH + 1)

    def test_rejects_invalid_purpose(self):
        with pytest.raises(StatusListError):
            StatusList(status_list_id=STATUS_URL, status_purpose="bogus")

    def test_rejects_empty_id(self):
        with pytest.raises(StatusListError):
            StatusList(status_list_id="")

    def test_default_state_all_zero(self):
        sl = StatusList(status_list_id=STATUS_URL)
        for idx in (0, 1, 7, 8, 100, 65535, DEFAULT_BITSTRING_LENGTH - 1):
            assert sl.get_status(idx) is False


class TestBitOperations:
    def test_set_and_get(self):
        sl = StatusList(status_list_id=STATUS_URL)
        sl.set_status(42, True)
        assert sl.get_status(42) is True
        assert sl.get_status(41) is False
        assert sl.get_status(43) is False

    def test_clear_after_set(self):
        sl = StatusList(status_list_id=STATUS_URL)
        sl.set_status(42, True)
        sl.set_status(42, False)
        assert sl.get_status(42) is False

    def test_first_and_last_bit(self):
        sl = StatusList(status_list_id=STATUS_URL)
        sl.revoke(0)
        sl.revoke(DEFAULT_BITSTRING_LENGTH - 1)
        assert sl.is_set(0) is True
        assert sl.is_set(DEFAULT_BITSTRING_LENGTH - 1) is True
        assert sl.is_set(1) is False
        assert sl.is_set(DEFAULT_BITSTRING_LENGTH - 2) is False

    def test_out_of_range_raises(self):
        sl = StatusList(status_list_id=STATUS_URL)
        with pytest.raises(StatusListError):
            sl.set_status(-1)
        with pytest.raises(StatusListError):
            sl.set_status(DEFAULT_BITSTRING_LENGTH)
        with pytest.raises(StatusListError):
            sl.get_status(DEFAULT_BITSTRING_LENGTH + 10_000)

    def test_revoke_reinstate_helpers(self):
        sl = StatusList(
            status_list_id=STATUS_URL,
            status_purpose=STATUS_PURPOSE_SUSPENSION,
        )
        sl.revoke(7)
        assert sl.is_set(7) is True
        sl.reinstate(7)
        assert sl.is_set(7) is False


class TestAllocation:
    def test_allocate_indices_are_sequential(self):
        sl = StatusList(status_list_id=STATUS_URL)
        assert sl.allocate_index() == 0
        assert sl.allocate_index() == 1
        assert sl.allocate_index() == 2

    def test_allocate_raises_when_exhausted(self):
        sl = StatusList(status_list_id=STATUS_URL, length=DEFAULT_BITSTRING_LENGTH)
        sl._next_index = DEFAULT_BITSTRING_LENGTH
        with pytest.raises(StatusListError):
            sl.allocate_index()


class TestEncoding:
    def test_encode_uses_multibase_prefix(self):
        sl = StatusList(status_list_id=STATUS_URL)
        encoded = sl.encode()
        assert encoded.startswith(MULTIBASE_BASE64URL_PREFIX)

    def test_encoded_payload_is_gzipped_bitstring(self):
        sl = StatusList(status_list_id=STATUS_URL)
        sl.revoke(100)
        encoded = sl.encode()
        payload = encoded[1:]
        padding = (-len(payload)) % 4
        compressed = base64.urlsafe_b64decode(payload + "=" * padding)
        raw = gzip.decompress(compressed)
        assert len(raw) == DEFAULT_BITSTRING_LENGTH // 8
        byte = raw[100 // 8]
        bit_pos = 7 - (100 % 8)
        assert byte & (1 << bit_pos) != 0

    def test_roundtrip_preserves_bits(self):
        sl = StatusList(status_list_id=STATUS_URL)
        for idx in (0, 1, 7, 8, 9, 16, 1023, 65535, DEFAULT_BITSTRING_LENGTH - 1):
            sl.revoke(idx)

        encoded = sl.encode()
        decoded = StatusList.decode(
            encoded=encoded,
            status_list_id=STATUS_URL,
            status_purpose=STATUS_PURPOSE_REVOCATION,
        )
        assert decoded.length == sl.length
        for idx in range(DEFAULT_BITSTRING_LENGTH):
            assert decoded.get_status(idx) == sl.get_status(idx)

    def test_decode_rejects_wrong_prefix(self):
        with pytest.raises(StatusListError):
            StatusList.decode(
                encoded="zNotMultibaseBase64Url",
                status_list_id=STATUS_URL,
            )

    def test_decode_rejects_corrupt_payload(self):
        with pytest.raises(StatusListError):
            StatusList.decode(
                encoded=MULTIBASE_BASE64URL_PREFIX + "$$$invalid$$$",
                status_list_id=STATUS_URL,
            )


class TestStatusListCredentialBuilder:
    def test_shape_matches_w3c(self):
        sl = StatusList(status_list_id=STATUS_URL)
        sl.revoke(7)
        vc = build_status_list_credential(
            issuer_did="did:web:issuer.example",
            status_list=sl,
        )

        assert vc["@context"] == ["https://www.w3.org/ns/credentials/v2"]
        assert vc["id"] == STATUS_URL
        assert "VerifiableCredential" in vc["type"]
        assert BITSTRING_STATUS_LIST_CREDENTIAL_TYPE in vc["type"]
        assert vc["issuer"] == "did:web:issuer.example"
        assert "validFrom" in vc
        assert "validUntil" in vc

        subj = vc["credentialSubject"]
        assert subj["id"] == f"{STATUS_URL}#list"
        assert subj["type"] == BITSTRING_STATUS_LIST_SUBJECT_TYPE
        assert subj["statusPurpose"] == STATUS_PURPOSE_REVOCATION
        assert subj["encodedList"].startswith(MULTIBASE_BASE64URL_PREFIX)


class TestStatusListEntryBuilder:
    def test_default_entry_shape(self):
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=42,
        )
        assert entry == {
            "id": f"{STATUS_URL}#42",
            "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
            "statusPurpose": STATUS_PURPOSE_REVOCATION,
            "statusListIndex": "42",
            "statusListCredential": STATUS_URL,
        }

    def test_index_is_serialized_as_string(self):
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=0,
        )
        assert entry["statusListIndex"] == "0"
        assert isinstance(entry["statusListIndex"], str)

    def test_rejects_negative_index(self):
        with pytest.raises(StatusListError):
            build_status_list_entry(
                status_list_credential=STATUS_URL,
                status_list_index=-1,
            )

    def test_rejects_invalid_purpose(self):
        with pytest.raises(StatusListError):
            build_status_list_entry(
                status_list_credential=STATUS_URL,
                status_list_index=0,
                status_purpose="bogus",
            )


class TestVerifyStatus:
    def _build(self, revoked_indices=()):
        sl = StatusList(status_list_id=STATUS_URL)
        for idx in revoked_indices:
            sl.revoke(idx)
        return sl, build_status_list_credential(
            issuer_did="did:web:issuer.example",
            status_list=sl,
        )

    def test_unset_bit_returns_false(self):
        _, vc = self._build()
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=10,
        )
        assert verify_status(credential_status=entry, status_list_credential=vc) is False

    def test_set_bit_returns_true(self):
        _, vc = self._build(revoked_indices=(10,))
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=10,
        )
        assert verify_status(credential_status=entry, status_list_credential=vc) is True

    def test_id_mismatch_raises(self):
        _, vc = self._build()
        entry = build_status_list_entry(
            status_list_credential="https://other.example/status/9",
            status_list_index=10,
        )
        with pytest.raises(StatusListError):
            verify_status(credential_status=entry, status_list_credential=vc)

    def test_purpose_mismatch_raises(self):
        sl = StatusList(
            status_list_id=STATUS_URL, status_purpose=STATUS_PURPOSE_SUSPENSION
        )
        vc = build_status_list_credential(
            issuer_did="did:web:issuer.example",
            status_list=sl,
        )
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=0,
            status_purpose=STATUS_PURPOSE_REVOCATION,
        )
        with pytest.raises(StatusListError):
            verify_status(credential_status=entry, status_list_credential=vc)

    def test_missing_index_raises(self):
        _, vc = self._build()
        entry = {
            "id": f"{STATUS_URL}#x",
            "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
            "statusPurpose": STATUS_PURPOSE_REVOCATION,
            "statusListCredential": STATUS_URL,
        }
        with pytest.raises(StatusListError):
            verify_status(credential_status=entry, status_list_credential=vc)

    def test_wrong_entry_type_raises(self):
        _, vc = self._build()
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=0,
        )
        entry["type"] = "NotAStatusListEntry"
        with pytest.raises(StatusListError):
            verify_status(credential_status=entry, status_list_credential=vc)


class TestVouchCredentialIntegration:
    def test_credential_status_is_embedded(self):
        sl = StatusList(status_list_id=STATUS_URL)
        idx = sl.allocate_index()
        entry = build_status_list_entry(
            status_list_credential=STATUS_URL,
            status_list_index=idx,
        )

        vc = build_vouch_credential(
            issuer_did="did:web:agent.example.com",
            intent={
                "action": "POST",
                "target": "https://api.example.com/orders",
                "resource": "order:42",
            },
            credential_status=entry,
        )

        assert vc["credentialStatus"] == entry
        assert vc["credentialStatus"]["statusListIndex"] == "0"

    def test_credential_status_omitted_when_none(self):
        vc = build_vouch_credential(
            issuer_did="did:web:agent.example.com",
            intent={
                "action": "POST",
                "target": "https://api.example.com/orders",
                "resource": "order:42",
            },
        )
        assert "credentialStatus" not in vc

    def test_end_to_end_revocation_flow(self):
        sl = StatusList(status_list_id=STATUS_URL)
        idx_a = sl.allocate_index()
        idx_b = sl.allocate_index()

        entry_a = build_status_list_entry(
            status_list_credential=STATUS_URL, status_list_index=idx_a
        )
        entry_b = build_status_list_entry(
            status_list_credential=STATUS_URL, status_list_index=idx_b
        )

        sl.revoke(idx_b)
        status_vc = build_status_list_credential(
            issuer_did="did:web:issuer.example", status_list=sl
        )

        assert verify_status(credential_status=entry_a, status_list_credential=status_vc) is False
        assert verify_status(credential_status=entry_b, status_list_credential=status_vc) is True


class TestPackageExports:
    def test_lazy_imports_resolve(self):
        import vouch

        assert vouch.StatusList.__name__ == "StatusList"
        assert vouch.StatusListError.__name__ == "StatusListError"
        assert vouch.FilesystemStatusListStore.__name__ == "FilesystemStatusListStore"
        assert vouch.StatusListFetcher.__name__ == "StatusListFetcher"
        assert vouch.StatusListFetchError.__name__ == "StatusListFetchError"
        assert callable(vouch.build_status_list_credential)
        assert callable(vouch.build_status_list_entry)
        assert callable(vouch.verify_status)


class TestStateDictPersistence:
    def test_roundtrip_preserves_bits_and_cursor(self):
        sl = StatusList(status_list_id=STATUS_URL)
        idx_a = sl.allocate_index()
        idx_b = sl.allocate_index()
        idx_c = sl.allocate_index()
        sl.revoke(idx_b)

        state = sl.to_state_dict()

        restored = StatusList.from_state_dict(state)
        assert restored.status_list_id == STATUS_URL
        assert restored.length == sl.length
        assert restored.get_status(idx_a) is False
        assert restored.get_status(idx_b) is True
        assert restored.get_status(idx_c) is False
        # Next allocation should resume after idx_c.
        assert restored.allocate_index() == idx_c + 1

    def test_state_dict_is_json_serializable(self):
        import json

        sl = StatusList(status_list_id=STATUS_URL)
        sl.revoke(100)
        state = sl.to_state_dict()
        encoded = json.dumps(state)  # must not raise
        assert json.loads(encoded) == state

    def test_rejects_missing_keys(self):
        with pytest.raises(StatusListError):
            StatusList.from_state_dict({"status_list_id": STATUS_URL})

    def test_rejects_invalid_next_index(self):
        sl = StatusList(status_list_id=STATUS_URL)
        state = sl.to_state_dict()
        state["next_index"] = -1
        with pytest.raises(StatusListError):
            StatusList.from_state_dict(state)


class TestFilesystemStatusListStore:
    def test_save_and_load_roundtrip(self, tmp_path):
        from vouch.status_list import FilesystemStatusListStore

        store_path = tmp_path / "status.json"
        store = FilesystemStatusListStore(str(store_path))

        sl = StatusList(status_list_id=STATUS_URL)
        sl.allocate_index()
        sl.allocate_index()
        sl.revoke(0)
        store.save(sl)

        assert store_path.exists()

        loaded = store.load()
        assert loaded.status_list_id == STATUS_URL
        assert loaded.get_status(0) is True
        assert loaded.get_status(1) is False
        # nextIndex preserved across save/load.
        assert loaded.allocate_index() == 2

    def test_save_is_atomic(self, tmp_path):
        from vouch.status_list import FilesystemStatusListStore

        store_path = tmp_path / "status.json"
        store = FilesystemStatusListStore(str(store_path))

        # First save creates the file.
        sl1 = StatusList(status_list_id=STATUS_URL)
        store.save(sl1)
        first_size = store_path.stat().st_size

        # Second save overwrites cleanly (no .tmp leftovers).
        sl2 = StatusList(status_list_id=STATUS_URL)
        for idx in range(10):
            sl2.allocate_index()
        sl2.revoke(0)
        sl2.revoke(5)
        store.save(sl2)

        # No leftover temp files.
        tmp_files = list(tmp_path.glob(".status_list-*.tmp"))
        assert tmp_files == []
        # File still readable.
        loaded = store.load()
        assert loaded.get_status(0) is True
        assert loaded.get_status(5) is True

    def test_load_missing_file_raises(self, tmp_path):
        from vouch.status_list import FilesystemStatusListStore

        store = FilesystemStatusListStore(str(tmp_path / "does-not-exist.json"))
        with pytest.raises(FileNotFoundError):
            store.load()


class TestStatusListFetcher:
    """
    Tests for the HTTP fetcher. Uses httpx.MockTransport so no real network calls.
    """

    def _make_fetcher(self, transport, **kwargs):
        import httpx

        from vouch.status_list_fetcher import StatusListFetcher

        client = httpx.Client(transport=transport)
        return StatusListFetcher(client=client, **kwargs)

    def _build_credential_response(self, revoked_indices=(7,)):
        sl = StatusList(status_list_id="https://issuer.example/status/1")
        for idx in revoked_indices:
            sl.revoke(idx)
        return build_status_list_credential(
            issuer_did="did:web:issuer.example",
            status_list=sl,
        )

    def test_fetch_hits_cache_on_repeat(self):
        import httpx

        calls = {"count": 0}
        credential = self._build_credential_response()

        def handler(request):
            calls["count"] += 1
            return httpx.Response(200, json=credential)

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport)
        url = "https://issuer.example/status/1"

        first = fetcher.get(url)
        second = fetcher.get(url)
        assert first == credential
        assert second == credential
        assert calls["count"] == 1  # cached the second time

    def test_force_refresh_skips_cache(self):
        import httpx

        calls = {"count": 0}
        credential = self._build_credential_response()

        def handler(request):
            calls["count"] += 1
            return httpx.Response(200, json=credential)

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport)
        url = "https://issuer.example/status/1"

        fetcher.get(url)
        fetcher.get(url, force_refresh=True)
        assert calls["count"] == 2

    def test_conditional_get_uses_etag(self):
        import httpx

        calls = []
        credential = self._build_credential_response()

        def handler(request):
            calls.append(dict(request.headers))
            if request.headers.get("if-none-match") == '"v1"':
                return httpx.Response(304)
            return httpx.Response(200, json=credential, headers={"etag": '"v1"'})

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport, cache_ttl_seconds=0)
        url = "https://issuer.example/status/1"

        first = fetcher.get(url)
        # cache_ttl=0 forces re-fetch but the entry is preserved for conditional headers.
        second = fetcher.get(url)

        assert first == credential
        assert second == credential
        assert calls[1].get("if-none-match") == '"v1"'

    def test_rejects_non_https(self):
        from vouch.status_list_fetcher import (
            StatusListFetcher,
            StatusListFetchError,
        )

        fetcher = StatusListFetcher()
        with pytest.raises(StatusListFetchError):
            fetcher.get("http://insecure.example/status/1")
        fetcher.close()

    def test_http_error_raises(self):
        import httpx

        from vouch.status_list_fetcher import StatusListFetchError

        def handler(request):
            return httpx.Response(503, text="boom")

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport)
        with pytest.raises(StatusListFetchError):
            fetcher.get("https://issuer.example/status/1")

    def test_oversized_body_rejected(self):
        import httpx

        from vouch.status_list_fetcher import StatusListFetchError

        big_body = b"{" + b" " * (10 * 1024 * 1024) + b"}"

        def handler(request):
            return httpx.Response(200, content=big_body)

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport, max_response_bytes=1024)
        with pytest.raises(StatusListFetchError):
            fetcher.get("https://issuer.example/status/1")

    def test_verify_status_with_fetched_credential(self):
        import httpx

        sl = StatusList(status_list_id="https://issuer.example/status/1")
        sl.revoke(42)
        credential = build_status_list_credential(
            issuer_did="did:web:issuer.example",
            status_list=sl,
        )

        def handler(request):
            return httpx.Response(200, json=credential)

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport)
        url = "https://issuer.example/status/1"

        revoked_entry = build_status_list_entry(
            status_list_credential=url,
            status_list_index=42,
        )
        active_entry = build_status_list_entry(
            status_list_credential=url,
            status_list_index=43,
        )

        fetched = fetcher.get(url)
        assert verify_status(credential_status=revoked_entry, status_list_credential=fetched) is True
        assert verify_status(credential_status=active_entry, status_list_credential=fetched) is False

    def test_invalidate(self):
        import httpx

        calls = {"count": 0}
        credential = self._build_credential_response()

        def handler(request):
            calls["count"] += 1
            return httpx.Response(200, json=credential)

        transport = httpx.MockTransport(handler)
        fetcher = self._make_fetcher(transport)
        url = "https://issuer.example/status/1"

        fetcher.get(url)
        fetcher.invalidate(url)
        fetcher.get(url)
        assert calls["count"] == 2
