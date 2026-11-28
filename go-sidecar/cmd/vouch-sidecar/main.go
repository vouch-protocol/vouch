// Command vouch-sidecar runs the Vouch Protocol signing sidecar as an HTTP
// server. It holds the agent's signing key in its own process, so the model
// that asks for signatures never has the key.
//
// Endpoints:
//
//	POST /sign         sign an intent and return a Verifiable Credential with
//	                   an eddsa-jcs-2022 Data Integrity proof. A request that
//	                   carries "payload" instead of "intent" returns the
//	                   composite JWS token, wrapped in the ML-KEM JWE vault in
//	                   sensitive mode.
//	POST /sign/hybrid  sign an intent with the post-quantum proof set: an
//	                   eddsa-jcs-2022 proof and an mldsa44-jcs-2024 proof.
//	GET  /health       readiness, the agent DID, and the last signature time
//	GET  /did          the agent DID and its verification method
//	GET  /pubkey       the public keys in Multikey form
//	GET  /.well-known/did.json  the DID document for the signing key
//
// Usage:
//
//	vouch-sidecar
//	vouch-sidecar --did did:web:agent.example.com --allowlist vouch-allowlist.json
//	vouch-sidecar --did did:web:agent.example.com --default-validity 10m --max-validity 2h
//	vouch-sidecar --did did:web:localhost --dev
//
// The sidecar signs as the identity `vouch init` saved in the keystore
// (~/.vouch/keys): the one for --did, or the only one there when --did is left
// out. A key can also come from --key (a private Ed25519 JWK file or an
// identity file) or from the VOUCH_ED25519_SEED environment variable (64 hex
// characters). With no key the sidecar does not start. For local testing,
// --dev uses a random key that lasts for this run only.
//
// The caller chooses how long each credential lasts with "validSeconds".
// --default-validity is what a caller gets when it names none, and
// --max-validity is the longest it may ask for.
//
// The server listens on 127.0.0.1 by default. To listen on another address
// pass --host and set VOUCH_SIDECAR_TOKEN; the signing endpoints then require
// the header "Authorization: Bearer <token>".
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Version of the Vouch Sidecar binary. First versioned release introduces
// the VC + Data Integrity credential path (eddsa-jcs-2022) and the
// hybrid post-quantum profile (hybrid-eddsa-mldsa44-jcs-2026) alongside
// the legacy composite JWS path.
const Version = "0.1.0"

const (
	seedEnv            = "VOUCH_ED25519_SEED"
	tokenEnv           = "VOUCH_SIDECAR_TOKEN"
	hostEnv            = "VOUCH_SIDECAR_HOST"
	defaultValidityEnv = "VOUCH_SIDECAR_DEFAULT_VALIDITY"
	maxValidityEnv     = "VOUCH_SIDECAR_MAX_VALIDITY"
	otelEndpointEnv    = "OTEL_EXPORTER_OTLP_ENDPOINT"

	defaultHost        = "127.0.0.1"
	defaultValidity    = 5 * time.Minute
	defaultMaxValidity = time.Hour
)

func main() {
	did := flag.String("did", "", "Agent DID. Optional when the keystore holds exactly one identity")
	host := flag.String("host", envOr(hostEnv, defaultHost), "Address to listen on")
	port := flag.Int("port", 8877, "HTTP listen port")
	keyPath := flag.String("key", "", "Path to a private Ed25519 JWK file or an identity file, in place of the keystore")
	dev := flag.Bool("dev", false, "Use a random key for this run only (local testing)")
	allowlistPath := flag.String("allowlist", "", "Path to an allow-list JSON file; only the actions it names are signed")
	validity := flag.Duration("default-validity", envDuration(defaultValidityEnv, defaultValidity),
		"How long a credential lasts when the caller does not say, for example 5m")
	maxValidity := flag.Duration("max-validity", envDuration(maxValidityEnv, defaultMaxValidity),
		"Longest validity a caller may ask for, for example 1h")
	hybrid := flag.Bool("hybrid", false, "Sign with the post-quantum proof set (Ed25519 plus ML-DSA-44)")
	otelEndpoint := flag.String("otel-endpoint", os.Getenv(otelEndpointEnv),
		"OpenTelemetry collector address for traces, for example http://localhost:4318")
	verbose := flag.Bool("verbose", false, "Log every request and the startup details")
	sensitive := flag.Bool("s", false, "Enable sensitive mode (ML-KEM JWE vault)")
	flag.BoolVar(sensitive, "sensitive", false, "Enable sensitive mode (ML-KEM JWE vault)")
	flag.Parse()

	// Read the secrets once, then drop them from the environment so nothing
	// started later by this process inherits them.
	seedHex := os.Getenv(seedEnv)
	token := os.Getenv(tokenEnv)
	os.Unsetenv(seedEnv)
	os.Unsetenv(tokenEnv)

	if err := checkExposure(*host, token); err != nil {
		fatal(err)
	}
	defaultSeconds, maxSeconds, err := validityWindow(*validity, *maxValidity)
	if err != nil {
		fatal(err)
	}

	id, err := resolveIdentity(keyOptions{
		did:         *did,
		keyPath:     *keyPath,
		seedHex:     seedHex,
		dev:         *dev,
		keystoreDir: defaultKeystoreDir(),
		random:      rand.Reader,
	})
	if err != nil {
		fatal(err)
	}

	s, err := signer.New(signer.Config{
		DID:                  id.did,
		Ed25519Seed:          id.seed,
		DefaultExpirySeconds: defaultSeconds,
	})
	if err != nil {
		fatal(fmt.Errorf("signer init failed: %w", err))
	}

	var allowed map[string]bool
	if *allowlistPath != "" {
		allowed, err = loadAllowlist(*allowlistPath, id.did)
		if err != nil {
			fatal(fmt.Errorf("allow-list: %w", err))
		}
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	var tracer *traceExporter
	if *otelEndpoint != "" {
		tracer, err = newTraceExporter(*otelEndpoint, logger)
		if err != nil {
			fatal(err)
		}
	}

	handler := newHandler(s, serverConfig{
		did:                 id.did,
		sensitive:           *sensitive,
		hybrid:              *hybrid,
		token:               token,
		keySource:           id.source,
		allowedActions:      allowed,
		defaultValidSeconds: defaultSeconds,
		maxValidSeconds:     maxSeconds,
		loopbackOnly:        isLoopbackHost(*host),
		logger:              logger,
		tracer:              tracer,
	})

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	publicKey, _ := s.PublicKeyMultikey()
	logger.Info("vouch-sidecar listening",
		"address", addr, "did", id.did, "key", id.source, "public_key", publicKey,
		"mode", modeLabel(*sensitive), "hybrid", *hybrid,
		"default_validity", validity.String(), "max_validity", maxValidity.String(),
	)
	if id.source == keyEphemeral {
		logger.Warn("dev mode: using a random key for this run only")
	}
	logger.Debug("startup details",
		"version", Version, "allowlist_actions", len(allowed), "token_required", token != "",
		"tracing", tracer != nil, "local_only", isLoopbackHost(*host),
	)

	// Stop cleanly on Ctrl-C or a container stop: finish requests in flight
	// and send any spans still queued.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()

	select {
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal(err)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}
	tracer.close()
}

// fatal prints a startup problem in plain words and exits.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vouch-sidecar:", err)
	os.Exit(1)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envDuration reads a duration such as "10m" from the environment.
func envDuration(name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		fatal(fmt.Errorf("%s must be a duration such as 5m or 1h", name))
	}
	return d
}

func modeLabel(sensitive bool) string {
	if sensitive {
		return "sensitive (ML-KEM-768 JWE vault)"
	}
	return "standard (composite JWS)"
}
