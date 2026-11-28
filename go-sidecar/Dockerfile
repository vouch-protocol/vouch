# Vouch Protocol signing sidecar.
#
# The published image is ghcr.io/vouch-protocol/sidecar. To build it yourself,
# run this from this directory:
#
#   docker build -t vouch-sidecar .
#
# Run next to the agent, with the agent's identity folder mounted read-only.
# `vouch init` saves identity files so only their owner can read them, so the
# container runs as your own user:
#
#   docker run --rm -p 127.0.0.1:8877:8877 \
#     --user "$(id -u):$(id -g)" -e HOME=/home/vouch \
#     -e VOUCH_SIDECAR_TOKEN \
#     -v "$HOME/.vouch/keys:/home/vouch/.vouch/keys:ro" \
#     ghcr.io/vouch-protocol/sidecar:0.1.0 --host 0.0.0.0
#
# Inside a container the sidecar has to listen on all addresses for the port
# mapping to reach it, so it requires VOUCH_SIDECAR_TOKEN. In a Kubernetes pod,
# where the agent shares localhost with the sidecar, leave --host and the token
# out.
#
# The image holds one static binary and runs as a non-root user.

# The build stage runs on the machine doing the build and cross-compiles for
# the target, so an arm64 image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.24 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/vouch-sidecar ./cmd/vouch-sidecar

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vouch-sidecar /vouch-sidecar
EXPOSE 8877
ENTRYPOINT ["/vouch-sidecar"]
