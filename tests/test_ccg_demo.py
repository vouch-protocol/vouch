"""The CCG demo scripts run offline and every case matches its expected outcome."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "ccg_demo"


@pytest.mark.parametrize("script", ["01_delegation.py", "02_trust_decay.py", "03_heartbeat.py"])
def test_demo_script_passes(script):
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, str(DEMO / script)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "UNEXPECTED" not in proc.stdout
    assert "matched the expected outcome" in proc.stdout
