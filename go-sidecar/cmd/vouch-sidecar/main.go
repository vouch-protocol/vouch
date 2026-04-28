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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Version of the Vouch Sidecar binary. First versioned release introduces
// the W3C VC + Data Integrity credential path (eddsa-jcs-2022) and the
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

	// Generate Ed25519 seed (in production, load from secure storage)
	seed := make([]byte, 32)
	if _, err := fmt.Sscanf(os.Getenv("VOUCH_ED25519_SEED"), "%x", &seed); err != nil {
		// If no seed in env, generate ephemeral (development mode)
		log.Println("warning: no VOUCH_ED25519_SEED set, generating ephemeral keys")
		if _, err := os.Stdin.Read(seed); err != nil {
			seed = make([]byte, 32)
			for i := range seed {
				seed[i] = byte(i)
			}
		}
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

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req signer.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		// CLI -s flag overrides per-request sensitive field
		if globalSensitive {
			req.Sensitive = true
		}

		out, err := s.Sign(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("signing failed: %v", err), http.StatusInternalServerError)
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

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("vouch-sidecar listening on %s (mode: %s)", addr, modeLabel(globalSensitive))
	log.Fatal(http.ListenAndServe(addr, nil))
}

func modeLabel(sensitive bool) string {
	if sensitive {
		return "sensitive (ML-KEM-768 JWE vault)"
	}
	return "standard (composite JWS)"
}
