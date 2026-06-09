#!/bin/sh
# Production supervisor for the Vouch Website Agent.
#
# Starts the Go sidecar in the background, then execs uvicorn in the
# foreground. If the sidecar dies, we kill uvicorn so the container exits
# and Fly restarts it (rather than the FastAPI serving 503s indefinitely).
set -eu

: "${VOUCH_AGENT_DID:?VOUCH_AGENT_DID is required (e.g. did:web:agent.vouch-protocol.com)}"
: "${VOUCH_ED25519_SEED:?VOUCH_ED25519_SEED is required (32-byte hex, set via fly secrets)}"

SIDECAR_PORT="${VOUCH_SIDECAR_PORT:-8877}"
APP_PORT="${PORT:-8000}"

echo "[start.sh] launching Go sidecar on 127.0.0.1:${SIDECAR_PORT} for ${VOUCH_AGENT_DID}"
vouch-sidecar --did "$VOUCH_AGENT_DID" --port "$SIDECAR_PORT" &
SIDECAR_PID=$!

# Forward signals to children
term() {
    echo "[start.sh] caught signal, terminating sidecar (pid=$SIDECAR_PID)"
    kill -TERM "$SIDECAR_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
    exit 0
}
trap term TERM INT

# If sidecar dies, exit so Fly restarts the whole container
watch_sidecar() {
    wait "$SIDECAR_PID"
    rc=$?
    echo "[start.sh] sidecar exited with $rc; killing self"
    kill -TERM 1 2>/dev/null || true
}
watch_sidecar &

# Tiny readiness wait so uvicorn's startup health-check on the sidecar
# doesn't race the sidecar's listen()
i=0
while [ $i -lt 30 ]; do
    if wget -q -O /dev/null --timeout=1 "http://127.0.0.1:${SIDECAR_PORT}/health" 2>/dev/null \
    || python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1',${SIDECAR_PORT}))==0 else 1)"; then
        echo "[start.sh] sidecar ready after ${i}s"
        break
    fi
    sleep 1
    i=$((i + 1))
done

echo "[start.sh] launching uvicorn on 0.0.0.0:${APP_PORT}"
exec uvicorn vouch_agent.main:app --host 0.0.0.0 --port "$APP_PORT" --no-server-header
