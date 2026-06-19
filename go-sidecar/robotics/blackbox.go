// Robot black-box log and kill-switch credential (Phase 5.5), Go.
//
// Mirrors vouch/robotics/blackbox.py and the TypeScript SDK. The black box is an
// append-only, AES-256-GCM-encrypted, hash-linked event log: payloads are
// confidential, the chain is tamper-evident without the key, and only the key
// opens the payloads. The encrypted blob is nonce(12) || ciphertext || tag(16),
// the same layout Python's AESGCM and Go's cipher.AEAD.Seal produce, so a
// Python- or TypeScript-written entry decrypts here and the JCS hash chain
// verifies across languages.
//
// The kill-switch credential is a verifiable emergency stop proving who issued it
// and, with an authority allowlist, that only an attested authority can trigger it.
package robotics

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

// Kill-switch and black-box constants.
const (
	KillSwitchType  = "KillSwitchCredential"
	BlackboxVersion = "1.0"
	EmergencyStop   = "emergency_stop"
)

// GenesisPrevHash is the prevHash of the first entry: multibase of 32 zero bytes.
var GenesisPrevHash = mb64(make([]byte, 32))

// BlackBoxError is returned for black-box failures (bad key, short ciphertext,
// failed decryption).
type BlackBoxError struct{ Msg string }

func (e *BlackBoxError) Error() string { return e.Msg }

// entryHash is the multibase SHA-256 over the JCS-canonical entry body, excluding
// the entryHash field itself.
func entryHash(body map[string]any) (string, error) {
	clean := make(map[string]any, len(body))
	for k, v := range body {
		if k != "entryHash" {
			clean[k] = v
		}
	}
	canon, err := signer.Canonicalize(clean)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return mb64(sum[:]), nil
}

// BlackBoxLog is an append-only, encrypted, hash-linked event log. The key is 32
// bytes (AES-256).
type BlackBoxLog struct {
	GenesisPrevHash string
	key             []byte
	gcm             cipher.AEAD
	entries         []map[string]any
	head            string
}

// NewBlackBoxLog builds a BlackBoxLog. An empty genesisPrevHash uses GenesisPrevHash.
func NewBlackBoxLog(key []byte, genesisPrevHash string) (*BlackBoxLog, error) {
	if len(key) != 32 {
		return nil, &BlackBoxError{"key must be 32 bytes (AES-256)"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if genesisPrevHash == "" {
		genesisPrevHash = GenesisPrevHash
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &BlackBoxLog{
		GenesisPrevHash: genesisPrevHash,
		key:             k,
		gcm:             gcm,
		head:            genesisPrevHash,
	}, nil
}

// Append encrypts payload, links it to the chain head, and returns the new entry.
// An empty timestamp uses now.
func (b *BlackBoxLog) Append(event string, payload map[string]any, timestamp string) (map[string]any, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plaintext, err := signer.Canonicalize(payload)
	if err != nil {
		return nil, err
	}
	// Seal returns ciphertext || tag; prepend the nonce for the on-disk layout.
	sealed := b.gcm.Seal(nil, nonce, plaintext, nil)
	blob := make([]byte, 0, len(nonce)+len(sealed))
	blob = append(blob, nonce...)
	blob = append(blob, sealed...)

	ts := timestamp
	if ts == "" {
		ts = iso(time.Now().UTC())
	}
	body := map[string]any{
		"version":    BlackboxVersion,
		"seq":        len(b.entries),
		"timestamp":  ts,
		"event":      event,
		"ciphertext": mb64(blob),
		"prevHash":   b.head,
	}
	h, err := entryHash(body)
	if err != nil {
		return nil, err
	}
	body["entryHash"] = h
	b.entries = append(b.entries, body)
	b.head = h
	return body, nil
}

// Head returns the current chain head hash.
func (b *BlackBoxLog) Head() string { return b.head }

// Entries returns a shallow copy of the entry list.
func (b *BlackBoxLog) Entries() []map[string]any {
	out := make([]map[string]any, len(b.entries))
	for i, e := range b.entries {
		c := make(map[string]any, len(e))
		for k, v := range e {
			c[k] = v
		}
		out[i] = c
	}
	return out
}

// OpenEntry decrypts a black-box entry with this log's key.
func (b *BlackBoxLog) OpenEntry(entry map[string]any) (map[string]any, error) {
	return OpenEntry(entry, b.key)
}

// OpenEntry decrypts a black-box entry payload and returns the original object.
func OpenEntry(entry map[string]any, key []byte) (map[string]any, error) {
	ctField, _ := entry["ciphertext"].(string)
	blob, err := unmb64(ctField)
	if err != nil {
		return nil, &BlackBoxError{"invalid ciphertext encoding: " + err.Error()}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns+gcm.Overhead() {
		return nil, &BlackBoxError{"ciphertext too short"}
	}
	nonce := blob[:ns]
	pt, err := gcm.Open(nil, nonce, blob[ns:], nil)
	if err != nil {
		return nil, &BlackBoxError{"decryption failed: " + err.Error()}
	}
	var payload map[string]any
	if err := json.Unmarshal(pt, &payload); err != nil {
		return nil, &BlackBoxError{"payload decode failed: " + err.Error()}
	}
	return payload, nil
}

// ChainResult is the outcome of VerifyBlackboxChain.
type ChainResult struct {
	OK     bool
	Reason string
}

// VerifyBlackboxChain verifies the hash chain over the (still-encrypted) entries.
// It is tamper-evident without the key. An empty genesisPrevHash uses GenesisPrevHash.
func VerifyBlackboxChain(entries []map[string]any, genesisPrevHash string) ChainResult {
	if genesisPrevHash == "" {
		genesisPrevHash = GenesisPrevHash
	}
	prev := genesisPrevHash
	for i, entry := range entries {
		if seq, ok := toInt(entry["seq"]); !ok || seq != i {
			return ChainResult{false, fmt.Sprintf("entry %d seq mismatch", i)}
		}
		if ph, _ := entry["prevHash"].(string); ph != prev {
			return ChainResult{false, fmt.Sprintf("entry %d prevHash does not link", i)}
		}
		want, err := entryHash(entry)
		if err != nil {
			return ChainResult{false, fmt.Sprintf("entry %d hash error", i)}
		}
		eh, _ := entry["entryHash"].(string)
		if eh != want {
			return ChainResult{false, fmt.Sprintf("entry %d entryHash mismatch (tampered)", i)}
		}
		prev = eh
	}
	return ChainResult{OK: true}
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Kill-switch credential
// ---------------------------------------------------------------------------

// BuildKillswitchOptions configures BuildKillswitchCredential.
type BuildKillswitchOptions struct {
	Target       string
	Reason       string
	Command      string   // "" defaults to EmergencyStop
	Scope        []string // nil omits the field
	ValidSeconds int      // 0 omits validUntil
	ValidFrom    time.Time
}

// BuildKillswitchCredential builds a signed KillSwitchCredential proving who
// issued an emergency stop.
func BuildKillswitchCredential(authority *signer.Signer, opts BuildKillswitchOptions) (map[string]any, error) {
	issued := opts.ValidFrom
	if issued.IsZero() {
		issued = time.Now().UTC()
	}
	command := opts.Command
	if command == "" {
		command = EmergencyStop
	}
	subject := map[string]any{
		"id":       opts.Target,
		"command":  command,
		"reason":   opts.Reason,
		"issuedBy": authority.DID(),
	}
	if opts.Scope != nil {
		subject["scope"] = strsToAny(opts.Scope)
	}
	cred := map[string]any{
		"@context":          []any{vcContextV2, vouchContextV1},
		"type":              []any{"VerifiableCredential", KillSwitchType},
		"issuer":            authority.DID(),
		"validFrom":         iso(issued),
		"credentialSubject": subject,
	}
	if opts.ValidSeconds > 0 {
		cred["validUntil"] = iso(issued.Add(time.Duration(opts.ValidSeconds) * time.Second))
	}
	return authority.AttachProof(cred)
}

// VerifyKillswitchCredential verifies a KillSwitchCredential. When
// trustedAuthorities is non-nil, the issuer DID MUST be in it, so only an
// attested authority can trigger the stop. Returns (ok, credentialSubject).
func VerifyKillswitchCredential(cred map[string]any, pub ed25519.PublicKey, trustedAuthorities map[string]bool) (bool, map[string]any) {
	if !hasType(cred["type"], KillSwitchType) {
		return false, nil
	}
	if ok, err := signer.VerifyDataIntegrityProof(cred, pub); err != nil || !ok {
		return false, nil
	}
	if trustedAuthorities != nil {
		issuer, _ := cred["issuer"].(string)
		if !trustedAuthorities[issuer] {
			return false, nil
		}
	}
	subject, _ := cred["credentialSubject"].(map[string]any)
	return true, subject
}
