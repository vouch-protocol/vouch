package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// maxBodyBytes bounds a /sign request body.
const maxBodyBytes = 1 << 20

// maxLoggedText bounds caller-supplied text copied into logs and spans.
const maxLoggedText = 128

// Where the ML-DSA-44 key comes from. Reported on /health.
const (
	pqSaved  = "saved"
	pqPerRun = "per-run"
	pqNone   = "none"
)

// noSavedPQKey explains how to give a saved identity its post-quantum key. The
// flags it names do not exist in releases that would replace the identity, so
// an older `vouch` stops with an error instead of making a new identity.
const noSavedPQKey = "this identity has no saved post-quantum key. Upgrade the Python package " +
	"(pip install -U vouch-protocol), then run `vouch init --did <your DID> --add-post-quantum-key`: " +
	"it keeps your key and adds the post-quantum one"

// upgradeAdvice is noSavedPQKey with the identity's own DID filled in.
func upgradeAdvice(did string) string {
	if did == "" {
		return noSavedPQKey
	}
	return "this identity has no saved post-quantum key. Upgrade the Python package " +
		"(pip install -U vouch-protocol), then run `vouch init --did " + did + " --add-post-quantum-key`: " +
		"it keeps your key and adds the post-quantum one"
}

// noPQKeyFor says what to do about a missing post-quantum key, by where the
// signing key came from.
func noPQKeyFor(source, did string) string {
	switch source {
	case keyFromEnv:
		return "--hybrid needs a post-quantum key, and " + seedEnv + " carries none. " +
			"Use the identity `vouch init` saved instead, or pass its file with --key"
	case keyFromFile:
		if did == "" {
			return "--hybrid needs a post-quantum key, and this key file carries none. " +
				"Pass an identity file from ~/.vouch/keys made by `vouch init` instead"
		}
	}
	return upgradeAdvice(did)
}

// ---------------------------------------------------------------------------
// Listening address, allow-list, validity
// ---------------------------------------------------------------------------

// isLoopbackHost reports whether host only accepts connections from this
// machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// checkExposure refuses a listening address that other machines can reach
// unless callers have to present a token.
func checkExposure(host, token string) error {
	if isLoopbackHost(host) || token != "" {
		return nil
	}
	return fmt.Errorf(
		"refusing to listen on %q without %s: other machines could ask this sidecar to sign. "+
			"Set %s, or keep the default --host %s",
		host, tokenEnv, tokenEnv, defaultHost,
	)
}

// loadAllowlist reads the action names from an allow-list file such as the
// vouch-allowlist.json that `vouch onboard` writes. If the file names an
// issuer it must be the DID this sidecar signs as.
func loadAllowlist(path, did string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		Actions []struct {
			Name string `json:"name"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if doc.Issuer != "" && doc.Issuer != did {
		return nil, fmt.Errorf("%s is for %s, but this sidecar signs as %s", path, doc.Issuer, did)
	}
	allowed := make(map[string]bool, len(doc.Actions))
	for _, a := range doc.Actions {
		if a.Name != "" {
			allowed[a.Name] = true
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%s names no actions", path)
	}
	return allowed, nil
}

// validityWindow turns the two validity settings into whole seconds. The
// default is what a caller gets when it does not ask for a duration; the
// maximum is the longest it may ask for.
func validityWindow(defaultValidity, maxValidity time.Duration) (defaultSeconds, maxSeconds int, err error) {
	if defaultValidity < time.Second {
		return 0, 0, errors.New("--default-validity must be at least one second, for example 5m")
	}
	if maxValidity < defaultValidity {
		return 0, 0, fmt.Errorf(
			"--default-validity (%s) is longer than --max-validity (%s): raise the maximum or lower the default",
			defaultValidity, maxValidity,
		)
	}
	return int(defaultValidity / time.Second), int(maxValidity / time.Second), nil
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

type serverConfig struct {
	did       string
	sensitive bool

	// hybrid makes /sign return the post-quantum proof set: an eddsa-jcs-2022
	// proof and an mldsa44-jcs-2024 proof on the same credential.
	hybrid bool

	// postQuantum says where the ML-DSA-44 key comes from: pqSaved with the
	// identity, pqPerRun (made for this process, as --dev does), or pqNone.
	postQuantum string

	// token, when set, must be presented as a bearer token on the signing
	// endpoints.
	token string

	// keySource is one of keyFromFile, keyFromEnv, keyFromKeystore,
	// keyEphemeral.
	keySource string

	// allowedActions, when non-nil, is the set of intent actions this sidecar
	// signs. nil signs any action.
	allowedActions map[string]bool

	// defaultValidSeconds is the validity a caller gets when it names none.
	// maxValidSeconds is the longest validity a caller may ask for.
	defaultValidSeconds int
	maxValidSeconds     int

	// loopbackOnly is true when the server listens on a loopback address.
	// Requests must then name a loopback host, which stops a web page from
	// reaching the sidecar through a hostname it points at this machine.
	loopbackOnly bool

	// logger receives one JSON line per event. nil discards them.
	logger *slog.Logger

	// tracer, when set, receives one span per signing request.
	tracer *traceExporter
}

// signBody is a signing request. "intent" asks for a Verifiable Credential;
// "payload" asks for the composite JWS token.
type signBody struct {
	Intent            map[string]any   `json:"intent"`
	ValidSeconds      int              `json:"validSeconds"`
	ValidSecondsSnake int              `json:"valid_seconds"`
	ReputationScore   *int             `json:"reputationScore"`
	DelegationChain   []map[string]any `json:"delegationChain"`
	CredentialStatus  map[string]any   `json:"credentialStatus"`

	Payload               map[string]any `json:"payload"`
	Sensitive             bool           `json:"sensitive"`
	RecipientKEMPublicKey string         `json:"recipient_kem_public_key"`
	ExpirySeconds         int            `json:"expiry_seconds"`
}

type handler struct {
	signer *signer.Signer
	cfg    serverConfig
	log    *slog.Logger

	// lastSigned is the time of the last successful signature, in Unix
	// nanoseconds. Zero until the first one.
	lastSigned atomic.Int64
}

// requestInfo collects what the handlers learn about one request, for the log
// line and the trace span written when it ends.
type requestInfo struct {
	action       string
	credentialID string
	validUntil   string
	proof        string
	refusal      string
}

type infoKey struct{}

func infoFrom(r *http.Request) *requestInfo {
	if info, ok := r.Context().Value(infoKey{}).(*requestInfo); ok {
		return info
	}
	return &requestInfo{}
}

func newHandler(s *signer.Signer, cfg serverConfig) http.Handler {
	if cfg.maxValidSeconds <= 0 {
		cfg.maxValidSeconds = int(defaultMaxValidity / time.Second)
	}
	if cfg.defaultValidSeconds <= 0 {
		cfg.defaultValidSeconds = int(defaultValidity / time.Second)
	}
	if cfg.defaultValidSeconds > cfg.maxValidSeconds {
		cfg.defaultValidSeconds = cfg.maxValidSeconds
	}
	if cfg.postQuantum == "" {
		cfg.postQuantum = pqPerRun
	}
	logger := cfg.logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	h := &handler{signer: s, cfg: cfg, log: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) { h.sign(w, r, cfg.hybrid) })
	mux.HandleFunc("/sign/hybrid", func(w http.ResponseWriter, r *http.Request) { h.sign(w, r, true) })
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/did", h.did)
	mux.HandleFunc("/pubkey", h.pubkey)
	mux.HandleFunc("/.well-known/did.json", h.didDocument)
	return h.observe(h.guardHost(mux))
}

// refuse answers with an error and remembers why, for the log.
func (h *handler) refuse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	infoFrom(r).refusal = reason
	http.Error(w, reason, status)
}

func (h *handler) guardHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.cfg.loopbackOnly {
			host := r.Host
			if name, _, err := net.SplitHostPort(r.Host); err == nil {
				host = name
			}
			if !isLoopbackHost(host) {
				h.refuse(w, r, http.StatusForbidden, "this sidecar only answers local requests")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) authorized(r *http.Request) bool {
	if h.cfg.token == "" {
		return true
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	// Compare digests so the check takes the same time whatever was sent.
	got := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	want := sha256.Sum256([]byte(h.cfg.token))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// sign handles /sign and /sign/hybrid. postQuantum selects the proof set for
// the credential form.
func (h *handler) sign(w http.ResponseWriter, r *http.Request, postQuantum bool) {
	if r.Method != http.MethodPost {
		h.refuse(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.refuse(w, r, http.StatusUnauthorized, "a valid bearer token is required")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		h.refuse(w, r, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	var req signBody
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.refuse(w, r, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	switch {
	case req.Intent != nil && req.Payload != nil:
		h.refuse(w, r, http.StatusBadRequest, "send either intent or payload, not both")
	case req.Intent != nil:
		h.signCredential(w, r, req, postQuantum)
	case req.Payload != nil && r.URL.Path != "/sign":
		h.refuse(w, r, http.StatusBadRequest, "this endpoint signs an intent")
	case req.Payload != nil:
		h.signToken(w, r, req)
	default:
		h.refuse(w, r, http.StatusBadRequest, "the request needs an intent with action, target and resource")
	}
}

// signCredential issues a Verifiable Credential for the requested intent.
func (h *handler) signCredential(w http.ResponseWriter, r *http.Request, req signBody, postQuantum bool) {
	info := infoFrom(r)
	if h.cfg.sensitive {
		h.refuse(w, r, http.StatusBadRequest, "sensitive mode signs the payload form only")
		return
	}
	if postQuantum && h.cfg.postQuantum == pqNone {
		h.refuse(w, r, http.StatusConflict, upgradeAdvice(h.cfg.did))
		return
	}
	for _, field := range []string{"action", "target", "resource"} {
		if v, ok := req.Intent[field].(string); !ok || v == "" {
			h.refuse(w, r, http.StatusBadRequest, fmt.Sprintf("intent.%s is required and must be a string", field))
			return
		}
	}
	info.action = clip(req.Intent["action"].(string))
	if !h.actionAllowed(req.Intent["action"]) {
		h.refuse(w, r, http.StatusForbidden, "this sidecar does not sign that action")
		return
	}
	requested := req.ValidSeconds
	if requested == 0 {
		requested = req.ValidSecondsSnake
	}
	validSeconds, ok := h.validity(w, r, requested)
	if !ok {
		return
	}

	opts := signer.SignOptions{
		Intent:           req.Intent,
		ValidSeconds:     validSeconds,
		ReputationScore:  req.ReputationScore,
		DelegationChain:  req.DelegationChain,
		CredentialStatus: req.CredentialStatus,
	}
	var cred map[string]any
	var err error
	if postQuantum {
		info.proof = "eddsa-jcs-2022+mldsa44-jcs-2024"
		cred, err = h.signer.SignHybrid(opts)
	} else {
		info.proof = "eddsa-jcs-2022"
		cred, err = h.signer.Sign(opts)
	}
	if err != nil {
		h.refuse(w, r, http.StatusInternalServerError, fmt.Sprintf("signing failed: %v", err))
		return
	}
	info.credentialID, _ = cred["id"].(string)
	info.validUntil, _ = cred["validUntil"].(string)
	h.lastSigned.Store(time.Now().UnixNano())
	writeJSON(w, cred)
}

// signToken issues the composite JWS token, wrapped in the JWE vault when
// sensitive mode is on.
func (h *handler) signToken(w http.ResponseWriter, r *http.Request, req signBody) {
	info := infoFrom(r)
	if action, ok := req.Payload["action"].(string); ok {
		info.action = clip(action)
	}
	if !h.actionAllowed(req.Payload["action"]) {
		h.refuse(w, r, http.StatusForbidden, "this sidecar does not sign that action")
		return
	}
	validSeconds, ok := h.validity(w, r, req.ExpirySeconds)
	if !ok {
		return
	}

	// The -s flag overrides the per-request sensitive field.
	sensitive := req.Sensitive || h.cfg.sensitive
	info.proof = "composite-jws"
	if sensitive {
		info.proof = "composite-jws+jwe"
	}
	out, err := h.signer.SignToken(signer.SignRequest{
		Payload:               req.Payload,
		Sensitive:             sensitive,
		RecipientKEMPublicKey: req.RecipientKEMPublicKey,
		ExpirySeconds:         validSeconds,
	})
	if err != nil {
		h.refuse(w, r, http.StatusInternalServerError, fmt.Sprintf("signing failed: %v", err))
		return
	}
	h.lastSigned.Store(time.Now().UnixNano())
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// actionAllowed reports whether action may be signed. With an allow-list
// configured, the action must be a string the list names.
func (h *handler) actionAllowed(action any) bool {
	if h.cfg.allowedActions == nil {
		return true
	}
	name, ok := action.(string)
	return ok && h.cfg.allowedActions[name]
}

// validity settles how long the credential lasts. The caller chooses; zero
// means "use the default". A negative value, or one past the maximum, gets a
// 400 and ok is false.
func (h *handler) validity(w http.ResponseWriter, r *http.Request, requested int) (seconds int, ok bool) {
	if requested == 0 {
		return h.cfg.defaultValidSeconds, true
	}
	if requested < 0 || requested > h.cfg.maxValidSeconds {
		h.refuse(w, r, http.StatusBadRequest, fmt.Sprintf(
			"validity must be between 1 and %d seconds; leave it out for the default of %d",
			h.cfg.maxValidSeconds, h.cfg.defaultValidSeconds,
		))
		return 0, false
	}
	return requested, true
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	var lastSignedAt any
	if at := h.lastSigned.Load(); at != 0 {
		lastSignedAt = time.Unix(0, at).UTC().Format(time.RFC3339)
	}
	writeJSON(w, map[string]any{
		"status":                 "operational",
		"ready":                  true,
		"mode":                   modeLabel(h.cfg.sensitive),
		"did":                    h.cfg.did,
		"key":                    h.cfg.keySource,
		"hybrid":                 h.cfg.hybrid,
		"postQuantumKey":         h.cfg.postQuantum,
		"defaultValiditySeconds": h.cfg.defaultValidSeconds,
		"maxValiditySeconds":     h.cfg.maxValidSeconds,
		"lastSignedAt":           lastSignedAt,
	})
}

func (h *handler) did(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"did":                h.cfg.did,
		"verificationMethod": h.signer.VerificationMethodID(),
	})
}

// pubkey returns the Ed25519 public key and, under "mldsa44", the ML-DSA-44
// public key that checks the second proof of a post-quantum credential.
func (h *handler) pubkey(w http.ResponseWriter, r *http.Request) {
	multikey, err := h.signer.PublicKeyMultikey()
	if err != nil {
		h.refuse(w, r, http.StatusInternalServerError, "public key unavailable")
		return
	}
	out := map[string]any{
		"verificationMethod": h.signer.VerificationMethodID(),
		"publicKeyMultibase": multikey,
	}
	if pq, err := h.signer.PublicKeyMLDSA44Multikey(); err == nil && h.cfg.postQuantum != pqNone {
		out["mldsa44"] = map[string]string{
			"verificationMethod": h.signer.MLDSA44VerificationMethodID(),
			"publicKeyMultibase": pq,
		}
	}
	writeJSON(w, out)
}

// didDocument serves the DID document for the signing key, with the public key
// as a Multikey. In hybrid mode it also lists the ML-DSA-44 key. Publish the
// same document at the DID's own address so verifiers can resolve it.
func (h *handler) didDocument(w http.ResponseWriter, r *http.Request) {
	multikey, err := h.signer.PublicKeyMultikey()
	if err != nil {
		h.refuse(w, r, http.StatusInternalServerError, "public key unavailable")
		return
	}
	method := h.signer.VerificationMethodID()
	methods := []map[string]string{{
		"id":                 method,
		"type":               "Multikey",
		"controller":         h.cfg.did,
		"publicKeyMultibase": multikey,
	}}
	assertion := []string{method}
	if h.cfg.hybrid {
		if pq, err := h.signer.PublicKeyMLDSA44Multikey(); err == nil {
			pqMethod := h.signer.MLDSA44VerificationMethodID()
			methods = append(methods, map[string]string{
				"id":                 pqMethod,
				"type":               "Multikey",
				"controller":         h.cfg.did,
				"publicKeyMultibase": pq,
			})
			assertion = append(assertion, pqMethod)
		}
	}
	writeJSON(w, map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
		},
		"id":                 h.cfg.did,
		"verificationMethod": methods,
		"assertionMethod":    assertion,
		"authentication":     []string{method},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Logging and tracing
// ---------------------------------------------------------------------------

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// observe writes the log line for each request and, for signing requests, the
// trace span. Logs carry the action and credential ID, never the key, the
// token, or the request body.
func (h *handler) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &requestInfo{}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), infoKey{}, info)))
		end := time.Now()

		h.log.Debug("request",
			"method", r.Method, "path", clip(r.URL.Path), "status", rec.status,
			"duration_ms", end.Sub(start).Milliseconds(),
		)
		if r.URL.Path != "/sign" && r.URL.Path != "/sign/hybrid" {
			return
		}
		if rec.status == http.StatusOK {
			h.log.Info("signed",
				"did", h.cfg.did, "action", info.action, "credential_id", info.credentialID,
				"valid_until", info.validUntil, "proof", info.proof,
			)
		} else {
			h.log.Warn("refused", "status", rec.status, "reason", info.refusal, "action", info.action)
		}
		h.trace(r, rec.status, start, end, info)
	})
}

// trace records the span for one signing request. A caller that sends a W3C
// traceparent header gets the span added to its own trace.
func (h *handler) trace(r *http.Request, status int, start, end time.Time, info *requestInfo) {
	if h.cfg.tracer == nil {
		return
	}
	traceID, parentSpanID, ok := parseTraceparent(r.Header.Get("traceparent"))
	if !ok {
		traceID, parentSpanID = newID(16), ""
	}
	spanID := newID(8)
	if traceID == "" || spanID == "" {
		return
	}
	attrs := []spanAttr{
		strAttr("http.request.method", r.Method),
		strAttr("url.path", r.URL.Path),
		intAttr("http.response.status_code", int64(status)),
		strAttr("vouch.did", h.cfg.did),
	}
	if info.action != "" {
		attrs = append(attrs, strAttr("vouch.intent.action", info.action))
	}
	if info.credentialID != "" {
		attrs = append(attrs, strAttr("vouch.credential.id", info.credentialID))
	}
	if info.proof != "" {
		attrs = append(attrs, strAttr("vouch.proof", info.proof))
	}
	h.cfg.tracer.record(span{
		traceID:      traceID,
		spanID:       spanID,
		parentSpanID: parentSpanID,
		name:         r.Method + " " + r.URL.Path,
		start:        start,
		end:          end,
		attrs:        attrs,
		failed:       status >= http.StatusInternalServerError,
	})
}

// clip bounds caller-supplied text before it is logged.
func clip(s string) string {
	if len(s) <= maxLoggedText {
		return s
	}
	return strings.ToValidUTF8(s[:maxLoggedText], "")
}
