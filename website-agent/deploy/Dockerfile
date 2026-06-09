# syntax=docker/dockerfile:1.7
# Production image for the Vouch Website Agent.
#
# Contains TWO processes:
#   - Go sidecar  (signs credentials, holds the Ed25519 key)
#   - FastAPI app (RAG + LLM, talks to the sidecar over 127.0.0.1:8877)
#
# A small start.sh supervises both: it execs uvicorn in the foreground and
# runs the sidecar as a background child. If either dies the container
# exits and Fly restarts it.
#
# Build context: the repo root (so we can COPY both go-sidecar/ and
# website-agent/). See deploy/README.md for the build command.

# -----------------------------------------------------------------------------
# Stage 1: build the Go sidecar
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS gobuild
WORKDIR /src
RUN apk add --no-cache git
COPY go-sidecar/go.mod go-sidecar/go.sum ./go-sidecar/
RUN cd go-sidecar && go mod download
COPY go-sidecar/ ./go-sidecar/
RUN cd go-sidecar && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/vouch-sidecar ./cmd/vouch-sidecar

# -----------------------------------------------------------------------------
# Stage 2: Python runtime + Go binary
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Run as non-root
RUN groupadd --system --gid 1000 vouch \
 && useradd  --system --uid 1000 --gid vouch --home-dir /app --shell /sbin/nologin vouch

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY website-agent/backend/pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -e ".[gemini]"

# Bring in the agent source + knowledge corpus
COPY website-agent/backend/vouch_agent /app/vouch_agent
COPY website-agent/backend/knowledge   /app/knowledge

# Bring in the Go sidecar binary
COPY --from=gobuild /out/vouch-sidecar /usr/local/bin/vouch-sidecar

# Supervisor / entrypoint
COPY website-agent/deploy/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# The DID document the FastAPI route serves at /.well-known/did.json.
# Generated locally by deploy/keygen.py and copied in at image build time
# (or mounted at runtime; see deploy/README.md).
COPY website-agent/deploy/did.json /app/did.json

# Drop privileges
USER vouch:vouch

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VOUCH_SIDECAR_URL=http://127.0.0.1:8877 \
    VOUCH_DID_DOCUMENT_PATH=/app/did.json

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/start.sh"]
