#!/usr/bin/env bash
# Run the three Vouch Protocol CCG demos in order. Each script exits non-zero if
# any case does not match its expected outcome, so this script does too.
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
for script in 01_delegation.py 02_trust_decay.py 03_heartbeat.py; do
  echo "=== ${script}"
  "${PYTHON}" "${script}"
  echo
done
echo "All demo cases matched their expected outcomes."
