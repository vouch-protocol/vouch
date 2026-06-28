"""
Smoke test for the flagship robotics demo: run it end to end and require every
invariant to hold. This keeps examples/robotics_demo.py from drifting out of sync
with the robotics API.
"""

import importlib.util
import os

import pytest

DEMO = os.path.join(os.path.dirname(__file__), "..", "examples", "robotics_demo.py")


def test_robotics_demo_all_checks_pass(capsys):
    spec = importlib.util.spec_from_file_location("robotics_demo", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # main() calls sys.exit(1) only if an invariant fails.
    try:
        module.main()
    except SystemExit as exc:  # pragma: no cover - only on a demo regression
        pytest.fail(f"robotics demo reported failing checks (exit {exc.code})")
    assert module._failures == 0
