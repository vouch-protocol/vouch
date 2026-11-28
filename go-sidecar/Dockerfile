# Vouch Protocol signing sidecar.
#
# Build from this directory:
#
#   docker build -t vouch-sidecar .
#
# Run next to the agent, with the agent's identity file mounted read-only:
#
#   docker run --rm -p 127.0.0.1:8877:8877 \
#     -e VOUCH_SIDECAR_TOKEN \
#     -v "$HOME/.vouch/keys:/home/nonroot/.vouch/keys:ro" \
#     vouch-sidecar --host 0.0.0.0
#
# Inside a container the sidecar has to listen on all addresses for the port
# mapping to reach it, so it requires VOUCH_SIDECAR_TOKEN. In a Kubernetes pod,
# where the agent shares localhost with the sidecar, leave --host and the token
# out.
#
# The image holds one static binary and runs as a non-root user.

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vouch-sidecar ./cmd/vouch-sidecar

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vouch-sidecar /vouch-sidecar
EXPOSE 8877
ENTRYPOINT ["/vouch-sidecar"]
