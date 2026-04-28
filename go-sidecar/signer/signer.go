// Package signer implements the Vouch Protocol security sidecar for autonomous
// AI agents. It produces composite JWS tokens (Ed25519 + ML-DSA-65) that bind
// agent identity to intent, and optionally wraps them inside a Post-Quantum
// JWE vault using ML-KEM-768 when the sensitive flag (-s) is invoked.
//
// Architecture:
//
//	Standard mode:   Payload -> Composite JWS (Ed25519 + ML-DSA) -> Output
//	Sensitive mode:  Payload -> Composite JWS -> ML-KEM JWE Vault -> Output
//
// The sensitive mode ensures that only the designated recipient, holding the
// corresponding ML-KEM private key, can decrypt and verify the signed identity
// envelope. Intermediate routers see only the JWE ciphertext and the ML-KEM
// encapsulation artifact -- never the agent's identity, intent, or signature.
package signer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// SignRequest represents an incoming request to the /sign endpoint.
type SignRequest struct {
	// Payload is the agent's intent data to be signed.
	Payload map[string]any `json:"payload"`

	// Sensitive triggers ML-KEM JWE wrapping when true (-s flag).
	Sensitive bool `json:"sensitive,omitempty"`

	// RecipientKEMPublicKey is the recipient's ML-KEM-768 encapsulation
	// key, required when Sensitive is true. Base64url-encoded.
	RecipientKEMPublicKey string `json:"recipient_kem_public_key,omitempty"`

	// ExpirySeconds overrides the default token validity period.
	ExpirySeconds int `json:"expiry_seconds,omitempty"`
}

// VouchToken is the standard (non-sensitive) output.
type VouchToken struct {
	// Token is the composite JWS in compact serialization.
	Token string `json:"token"`

	// Mode indicates the protection level applied.
	Mode string `json:"mode"` // "standard" or "sensitive"
}

// SensitiveVault is the JWE output when the sensitive flag is active.
type SensitiveVault struct {
	// Mode is always "sensitive".
	Mode string `json:"mode"`

	// Algorithm identifies the KEM used for key encapsulation.
	Algorithm string `json:"alg"`

	// Encryption identifies the content encryption algorithm.
	Encryption string `json:"enc"`

	// KEMCiphertext is the ML-KEM encapsulation artifact (base64url).
	// The recipient decapsulates this with their private key to recover
	// the shared secret.
	KEMCiphertext string `json:"kem_ciphertext"`

	// Nonce is the AES-256-GCM initialization vector (base64url).
	Nonce string `json:"nonce"`

	// Ciphertext is the AES-256-GCM encrypted composite JWS (base64url).
	Ciphertext string `json:"ciphertext"`

	// Tag is the AES-256-GCM authentication tag (base64url).
	Tag string `json:"tag"`
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

// Signer is the Vouch Protocol security sidecar. It holds the agent's
// classical (Ed25519) and post-quantum (ML-DSA-65) signing keys and
// produces composite JWS tokens, optionally wrapped in a PQ JWE vault.
//
// In addition, the Signer may carry an ML-DSA-44 keypair used by the
// hybrid-eddsa-mldsa44-jcs-2026 cryptosuite (W3C CG Report §13.2). The
// ML-DSA-44 key is separate from the ML-DSA-65 key used by the legacy
// composite JWS path: different parameter set, different deployment
// profile (level-1 PQ security, smaller signatures, W3C-track usage).
type Signer struct {
	did            string
	defaultExpiry  int
	ed25519Private ed25519.PrivateKey
	ed25519Public  ed25519.PublicKey
	mldsaPrivate   *mldsa65.PrivateKey
	mldsaPublic    *mldsa65.PublicKey

	// ML-DSA-44 keypair for the hybrid Data Integrity profile.
	// Generated on demand if the caller did not supply one.
	mldsa44Private *mldsa44.PrivateKey
	mldsa44Public  *mldsa44.PublicKey
}

// Config holds the initialization parameters for a Signer.
type Config struct {
	// DID is the agent's Decentralized Identifier (e.g. did:web:agent.example.com).
	DID string

	// Ed25519Seed is the 32-byte seed for the classical signing key.
	Ed25519Seed []byte

	// MLDSAPrivateKey is the ML-DSA-65 private key. If nil, a fresh
	// keypair is generated. Used by the legacy composite JWS path.
	MLDSAPrivateKey *mldsa65.PrivateKey

	// MLDSA44PrivateKey is the ML-DSA-44 private key used by the hybrid
	// Data Integrity profile (W3C CG Report §13.2). If nil, a fresh
	// keypair is generated. Independent from MLDSAPrivateKey.
	MLDSA44PrivateKey *mldsa44.PrivateKey

	// DefaultExpirySeconds sets the default token validity (default: 300).
	DefaultExpirySeconds int
}

// New creates a Signer from the provided configuration.
func New(cfg Config) (*Signer, error) {
	if cfg.DID == "" {
		return nil, errors.New("vouch: DID is required")
	}
	if len(cfg.Ed25519Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("vouch: Ed25519Seed must be %d bytes", ed25519.SeedSize)
	}

	edPriv := ed25519.NewKeyFromSeed(cfg.Ed25519Seed)
	edPub := edPriv.Public().(ed25519.PublicKey)

	mlPriv := cfg.MLDSAPrivateKey
	var mlPub *mldsa65.PublicKey
	if mlPriv == nil {
		var err error
		mlPub, mlPriv, err = mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("vouch: ML-DSA-65 keygen failed: %w", err)
		}
	} else {
		mlPub = mlPriv.Public().(*mldsa65.PublicKey)
	}

	ml44Priv := cfg.MLDSA44PrivateKey
	var ml44Pub *mldsa44.PublicKey
	if ml44Priv == nil {
		var err error
		ml44Pub, ml44Priv, err = mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("vouch: ML-DSA-44 keygen failed: %w", err)
		}
	} else {
		ml44Pub = ml44Priv.Public().(*mldsa44.PublicKey)
	}

	expiry := cfg.DefaultExpirySeconds
	if expiry <= 0 {
		expiry = 300
	}

	return &Signer{
		did:            cfg.DID,
		defaultExpiry:  expiry,
		ed25519Private: edPriv,
		ed25519Public:  edPub,
		mldsaPrivate:   mlPriv,
		mldsaPublic:    mlPub,
		mldsa44Private: ml44Priv,
		mldsa44Public:  ml44Pub,
	}, nil
}

// ---------------------------------------------------------------------------
// Composite JWS (Ed25519 + ML-DSA-65)
// ---------------------------------------------------------------------------

// joseHeader is the protected header for the composite JWS.
type joseHeader struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	KeyID     string   `json:"kid"`
	Composite []string `json:"vouch_composite_alg"`
}

// Claims is the JWT claims payload for a Vouch Token.
type Claims struct {
	JTI   string         `json:"jti"`
	ISS   string         `json:"iss"`
	SUB   string         `json:"sub"`
	IAT   int64          `json:"iat"`
	NBF   int64          `json:"nbf"`
	EXP   int64          `json:"exp"`
	Vouch map[string]any `json:"vouch"`
}

// compositeSignature holds both signature components.
type compositeSignature struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa65"`
}

// compositeJWS is the full composite JWS structure.
type compositeJWS struct {
	Protected string             `json:"protected"`
	Payload   string             `json:"payload"`
	Signature compositeSignature `json:"signature"`
}

// Sign produces a Vouch Token. If req.Sensitive is true and a valid
// recipient ML-KEM public key is provided, the composite JWS is wrapped
// inside an ML-KEM-768 / AES-256-GCM JWE vault.
func (s *Signer) Sign(req SignRequest) ([]byte, error) {
	// 1. Build the composite JWS
	jwsBytes, err := s.buildCompositeJWS(req)
	if err != nil {
		return nil, fmt.Errorf("vouch: JWS construction failed: %w", err)
	}

	if !req.Sensitive {
		// Standard mode: return the composite JWS directly.
		out := VouchToken{
			Token: string(jwsBytes),
			Mode:  "standard",
		}
		return json.MarshalIndent(out, "", "  ")
	}

	// 2. Sensitive mode: wrap JWS inside ML-KEM JWE vault.
	if req.RecipientKEMPublicKey == "" {
		return nil, errors.New("vouch: recipient_kem_public_key is required when sensitive=true")
	}

	vault, err := s.wrapInJWEVault(jwsBytes, req.RecipientKEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("vouch: JWE vault construction failed: %w", err)
	}

	return json.MarshalIndent(vault, "", "  ")
}

// buildCompositeJWS creates the dual-signed JWS (Ed25519 + ML-DSA-65).
func (s *Signer) buildCompositeJWS(req SignRequest) ([]byte, error) {
	now := time.Now().Unix()
	expiry := s.defaultExpiry
	if req.ExpirySeconds > 0 {
		expiry = req.ExpirySeconds
	}

	// Protected header
	hdr := joseHeader{
		Algorithm: "EdDSA+ML-DSA-65",
		Type:      "vouch+jwt",
		KeyID:     s.did,
		Composite: []string{"EdDSA", "ML-DSA-65"},
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	hdrB64 := base64url(hdrJSON)

	// Claims payload
	c := Claims{
		JTI: generateTokenID(),
		ISS: s.did,
		SUB: s.did,
		IAT: now,
		NBF: now,
		EXP: now + int64(expiry),
		Vouch: map[string]any{
			"version": "1.0",
			"payload": req.Payload,
		},
	}
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	payloadB64 := base64url(claimsJSON)

	// Signing input: header.payload (standard JWS format)
	signingInput := []byte(hdrB64 + "." + payloadB64)

	// Ed25519 signature
	edSig := ed25519.Sign(s.ed25519Private, signingInput)

	// ML-DSA-65 signature (using crypto.Signer interface)
	mlSig, err := s.mldsaPrivate.Sign(rand.Reader, signingInput, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	// Assemble composite JWS
	jws := compositeJWS{
		Protected: hdrB64,
		Payload:   payloadB64,
		Signature: compositeSignature{
			Ed25519: base64url(edSig),
			MLDSA65: base64url(mlSig),
		},
	}

	return json.Marshal(jws)
}

// ---------------------------------------------------------------------------
// ML-KEM-768 JWE Vault (using Go 1.24 crypto/mlkem)
// ---------------------------------------------------------------------------

// wrapInJWEVault encrypts the composite JWS inside a PQ JWE vault.
//
// Process:
//  1. Decode the recipient's ML-KEM-768 encapsulation (public) key.
//  2. Encapsulate a 32-byte shared secret using ML-KEM-768.
//  3. Derive an AES-256-GCM key from the shared secret via SHA-256.
//  4. Encrypt the composite JWS using AES-256-GCM.
//  5. Return the JWE vault containing ciphertext + KEM ciphertext.
func (s *Signer) wrapInJWEVault(jwsData []byte, recipientPubKeyB64 string) (*SensitiveVault, error) {
	// Step 1: Decode recipient's ML-KEM-768 encapsulation key
	ekBytes, err := base64decode(recipientPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key encoding: %w", err)
	}

	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 encapsulation key: %w", err)
	}

	// Step 2: Encapsulate shared secret
	sharedKey, kemCiphertext := ek.Encapsulate()

	// Step 3: Derive AES-256-GCM key from shared secret
	// The ML-KEM shared key is 32 bytes. We pass it through SHA-256
	// for domain separation.
	aesKey := sha256.Sum256(sharedKey)

	// Step 4: Encrypt composite JWS with AES-256-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("AES cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes for GCM
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// GCM Seal appends the auth tag to the ciphertext
	sealed := gcm.Seal(nil, nonce, jwsData, nil)

	// Split ciphertext and tag (tag is last 16 bytes)
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	// Step 5: Assemble the JWE vault
	return &SensitiveVault{
		Mode:          "sensitive",
		Algorithm:     "ML-KEM-768",
		Encryption:    "A256GCM",
		KEMCiphertext: base64url(kemCiphertext),
		Nonce:         base64url(nonce),
		Ciphertext:    base64url(ciphertext),
		Tag:           base64url(tag),
	}, nil
}

// ---------------------------------------------------------------------------
// Decapsulation & Verification (Recipient Side)
// ---------------------------------------------------------------------------

// DecryptVault decrypts a SensitiveVault using the recipient's ML-KEM
// private key, returning the inner composite JWS.
func DecryptVault(vault *SensitiveVault, recipientDK *mlkem.DecapsulationKey768) ([]byte, error) {
	if vault.Algorithm != "ML-KEM-768" {
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", vault.Algorithm)
	}
	if vault.Encryption != "A256GCM" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", vault.Encryption)
	}

	// Decode KEM ciphertext
	kemCT, err := base64decode(vault.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM ciphertext: %w", err)
	}

	// Decapsulate shared secret
	sharedKey, err := recipientDK.Decapsulate(kemCT)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	// Derive AES key (same derivation as encryption side)
	aesKey := sha256.Sum256(sharedKey)

	// Decode nonce, ciphertext, and tag
	nonce, err := base64decode(vault.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	ciphertextBytes, err := base64decode(vault.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	tag, err := base64decode(vault.Tag)
	if err != nil {
		return nil, fmt.Errorf("invalid tag: %w", err)
	}

	// Reconstruct sealed data (ciphertext + tag) for GCM Open
	sealed := append(ciphertextBytes, tag...)

	// Decrypt
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("AES cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (tampered or wrong key): %w", err)
	}

	return plaintext, nil
}

// VerifyCompositeJWS verifies both signatures in a composite JWS.
// Returns the decoded claims payload on success.
func VerifyCompositeJWS(jwsData []byte, edPub ed25519.PublicKey, mlPub *mldsa65.PublicKey) (*Claims, error) {
	var j compositeJWS
	if err := json.Unmarshal(jwsData, &j); err != nil {
		return nil, fmt.Errorf("invalid JWS structure: %w", err)
	}

	signingInput := []byte(j.Protected + "." + j.Payload)

	// Verify Ed25519
	edSig, err := base64decode(j.Signature.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 signature encoding: %w", err)
	}
	if !ed25519.Verify(edPub, signingInput, edSig) {
		return nil, errors.New("Ed25519 signature verification failed")
	}

	// Verify ML-DSA-65
	mlSig, err := base64decode(j.Signature.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-DSA signature encoding: %w", err)
	}
	if !mldsa65.Verify(mlPub, signingInput, nil, mlSig) {
		return nil, errors.New("ML-DSA-65 signature verification failed")
	}

	// Decode payload
	payloadJSON, err := base64decode(j.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return nil, fmt.Errorf("invalid claims JSON: %w", err)
	}

	return &c, nil
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// base64url encodes bytes to base64url without padding.
func base64url(data []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}

// base64decode decodes a base64url string without padding.
func base64decode(s string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
}

// generateTokenID produces a unique token identifier.
func generateTokenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GenerateKEMKeyPair generates a fresh ML-KEM-768 keypair for recipients.
// Returns the decapsulation key and the base64url-encoded encapsulation
// (public) key suitable for use in SignRequest.RecipientKEMPublicKey.
func GenerateKEMKeyPair() (*mlkem.DecapsulationKey768, string, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, "", fmt.Errorf("ML-KEM keygen failed: %w", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	return dk, base64url(ekBytes), nil
}
