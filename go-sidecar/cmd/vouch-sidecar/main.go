// Command vouch-sidecar runs the Vouch Protocol security sidecar as an
// HTTP server. It exposes a /sign endpoint that produces composite JWS
// tokens, optionally wrapped in a Post-Quantum JWE vault when the
// -s (--sensitive) flag is active.
//
// Usage:
//
//	vouch-sidecar --did did:web:agent.example.com --port 8877
//	vouch-sidecar --did did:web:agent.example.com --port 8877 -s
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// maxSignBody bounds the /sign request body to prevent memory-exhaustion DoS.
const maxSignBody = 1 << 20 // 1 MiB

// isLoopbackHost reports whether the bind host is a loopback address. The
// sidecar refuses to run unauthenticated on any non-loopback interface.
func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

// Version of the Vouch Sidecar binary. First versioned release introduces
// the VC + Data Integrity credential path (eddsa-jcs-2022) and the
// hybrid post-quantum profile (hybrid-eddsa-mldsa44-jcs-2026) alongside
// the legacy composite JWS path.
const Version = "0.1.0"

func main() {
	did := flag.String("did", "", "Agent DID (required)")
	port := flag.Int("port", 8877, "HTTP listen port")
	sensitive := flag.Bool("s", false, "Enable sensitive mode (ML-KEM JWE vault)")
	flag.BoolVar(sensitive, "sensitive", false, "Enable sensitive mode (ML-KEM JWE vault)")
	flag.Parse()

	if *did == "" {
		fmt.Fprintln(os.Stderr, "error: --did is required")
		flag.Usage()
		os.Exit(1)
	}

	// Load the Ed25519 seed from secure configuration. We FAIL CLOSED: the
	// sidecar refuses to start without an explicitly configured 32-byte seed.
	// A predictable or deterministic key would let anyone forge this agent's
	// credentials, so there is no development fallback.
	seedHex := strings.TrimSpace(os.Getenv("VOUCH_ED25519_SEED"))
	if seedHex == "" {
		log.Fatal("error: VOUCH_ED25519_SEED is required (64 hex chars / 32 bytes). Refusing to start without a configured signing key.")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("error: VOUCH_ED25519_SEED must be exactly 64 hex characters (32 bytes)")
	}

	// Bind host and optional bearer token for the /sign endpoint. Default to
	// loopback; refuse to expose an unauthenticated signer on a routable
	// interface.
	host := os.Getenv("VOUCH_SIDECAR_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	authToken := os.Getenv("VOUCH_SIDECAR_TOKEN")
	if !isLoopbackHost(host) && authToken == "" {
		log.Fatalf("error: refusing to bind %s without VOUCH_SIDECAR_TOKEN; an unauthenticated signing endpoint must stay on loopback", host)
	}
	if authToken == "" {
		log.Println("warning: VOUCH_SIDECAR_TOKEN not set; /sign is unauthenticated (loopback only)")
	}

	s, err := signer.New(signer.Config{
		DID:                  *did,
		Ed25519Seed:          seed,
		DefaultExpirySeconds: 300,
	})
	if err != nil {
		log.Fatalf("signer init failed: %v", err)
	}

	globalSensitive := *sensitive

	// checkAuth enforces the bearer token when one is configured, using a
	// constant-time comparison to avoid a timing oracle on the token.
	checkAuth := func(r *http.Request) bool {
		if authToken == "" {
			return true
		}
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			return false
		}
		got := h[len(prefix):]
		return subtle.ConstantTimeCompare([]byte(got), []byte(authToken)) == 1
	}

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !checkAuth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Bound the request body to prevent memory-exhaustion DoS.
		r.Body = http.MaxBytesReader(w, r.Body, maxSignBody)

		var req signer.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Do not echo internal parser detail back to the client.
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// CLI -s flag overrides per-request sensitive field
		if globalSensitive {
			req.Sensitive = true
		}

		out, err := s.Sign(req)
		if err != nil {
			log.Printf("signing failed: %v", err)
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "operational",
			"mode":   modeLabel(globalSensitive),
			"did":    *did,
		})
	})

	addr := fmt.Sprintf("%s:%d", host, *port)
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("vouch-sidecar listening on %s (mode: %s)", addr, modeLabel(globalSensitive))
	log.Fatal(srv.ListenAndServe())
}

func modeLabel(sensitive bool) string {
	if sensitive {
		return "sensitive (ML-KEM-768 JWE vault)"
	}
	return "standard (composite JWS)"
}
