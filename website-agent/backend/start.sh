#!/bin/sh
# Start the signing sidecar and the chat server in one container.
#
# The sidecar gets VOUCH_AGENT_SIGNING_KEY and listens on localhost only.
# The chat server starts with that variable removed from its environment,
# so the process that talks to the language model never holds the key.
# If either process exits, the container exits and the platform restarts it.
set -eu

if [ -z "${VOUCH_AGENT_SIGNING_KEY:-}" ]; then
    echo "VOUCH_AGENT_SIGNING_KEY is not set; refusing to start without a signing key" >&2
    exit 1
fi

python -m vouch_agent.sidecar --host 127.0.0.1 --port 8877 &
SIDECAR_PID=$!

env -u VOUCH_AGENT_SIGNING_KEY \
    VOUCH_SIDECAR_URL=http://127.0.0.1:8877 \
    uvicorn vouch_agent.main:app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!

trap 'kill "$SIDECAR_PID" "$SERVER_PID" 2>/dev/null' INT TERM

# Exit as soon as either process stops.
while kill -0 "$SIDECAR_PID" 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null; do
    sleep 2
done
kill "$SIDECAR_PID" "$SERVER_PID" 2>/dev/null || true
exit 1
