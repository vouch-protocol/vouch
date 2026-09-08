"""Tests for how vouch.threshold loads (or refuses) the native FROST library.

These are deliberately separate from test_threshold.py. That module is gated on
the native library being present, and the behaviour under test here is what
happens when it is *absent or unusable* - which is exactly the case the gate
skips.

The regression these guard: a stale build of libvouch_core_uniffi loads fine and
then raises AttributeError on the first symbol lookup. That escaped as an
AttributeError instead of the documented ThresholdError, which broke pytest at
collection time rather than skipping cleanly.
"""

import ctypes
import ctypes.util

import pytest

import vouch.threshold as threshold


@pytest.fixture(autouse=True)
def _reset_loader_state():
    """Keep loader caching from leaking between tests, in either direction."""
    saved_lib = threshold._LIB
    saved_attempted = threshold._LIB_LOAD_ATTEMPTED
    threshold._LIB = None
    threshold._LIB_LOAD_ATTEMPTED = False
    yield
    threshold._LIB = saved_lib
    threshold._LIB_LOAD_ATTEMPTED = saved_attempted


def _no_system_library(monkeypatch):
    monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)


def test_missing_library_raises_threshold_error(monkeypatch):
    """No library anywhere -> the documented ThresholdError."""
    monkeypatch.setattr(threshold, "_candidate_paths", lambda: [])
    _no_system_library(monkeypatch)

    with pytest.raises(threshold.ThresholdError) as caught:
        threshold.generate_key(2, 3)

    assert "cargo build --release" in str(caught.value)


def test_stale_library_raises_threshold_error_not_attribute_error(monkeypatch, tmp_path):
    """A library missing a bound symbol must not leak AttributeError.

    A stale shared object loads successfully and only fails when a symbol this
    module binds is looked up. That must surface as ThresholdError so callers -
    including the skip guard in test_threshold.py - can handle it.
    """
    fake = tmp_path / "libvouch_core_uniffi.so"
    fake.write_bytes(b"")

    class StaleLibrary:
        """Loads, but exports nothing - like a build predating the symbol."""

        _name = str(fake)

        def __getattr__(self, name):
            raise AttributeError(f"{fake}: undefined symbol: {name}")

    monkeypatch.setattr(threshold, "_candidate_paths", lambda: [str(fake)])
    monkeypatch.setattr(ctypes, "CDLL", lambda path: StaleLibrary())
    _no_system_library(monkeypatch)

    with pytest.raises(threshold.ThresholdError) as caught:
        threshold.generate_key(2, 3)

    message = str(caught.value)
    assert "needs rebuilding" in message
    assert "undefined symbol" in message
    assert str(fake) in message


def test_stale_candidate_does_not_shadow_a_usable_one(monkeypatch, tmp_path):
    """A stale library earlier in the search order must not win.

    The loader should treat it as unusable and keep looking, rather than
    binding to it or giving up.
    """
    stale_path = tmp_path / "stale.so"
    good_path = tmp_path / "good.so"
    stale_path.write_bytes(b"")
    good_path.write_bytes(b"")

    class StaleLibrary:
        def __getattr__(self, name):
            raise AttributeError(f"{stale_path}: undefined symbol: {name}")

    class GoodLibrary:
        _name = str(good_path)

        def __getattr__(self, name):
            return type("Fn", (), {"argtypes": None, "restype": None})()

    def fake_cdll(path):
        return StaleLibrary() if path == str(stale_path) else GoodLibrary()

    monkeypatch.setattr(threshold, "_candidate_paths", lambda: [str(stale_path), str(good_path)])
    monkeypatch.setattr(ctypes, "CDLL", fake_cdll)
    monkeypatch.setattr(threshold, "_configure_signatures", lambda lib: lib.probe)
    _no_system_library(monkeypatch)

    assert threshold._load_library()._name == str(good_path)


def test_failed_configuration_is_not_cached(monkeypatch, tmp_path):
    """A library that fails configuration must not be published to _LIB.

    Caching a partially-configured handle would make the failure sticky: the
    early return at the top of _load_library would hand it to every later call.
    """
    fake = tmp_path / "libvouch_core_uniffi.so"
    fake.write_bytes(b"")

    class StaleLibrary:
        def __getattr__(self, name):
            raise AttributeError(f"{fake}: undefined symbol: {name}")

    monkeypatch.setattr(threshold, "_candidate_paths", lambda: [str(fake)])
    monkeypatch.setattr(ctypes, "CDLL", lambda path: StaleLibrary())
    _no_system_library(monkeypatch)

    with pytest.raises(threshold.ThresholdError):
        threshold._load_library()

    assert threshold._LIB is None, "a library that failed configuration was cached"
