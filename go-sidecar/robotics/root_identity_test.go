package robotics

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

var robotAttrs = map[string]any{
	"make":   "Acme Robotics",
	"model":  "AR-7",
	"serial": "SN-000123",
	"owner":  "did:web:acme.example.com",
}

// didKeySigner builds a did:key Signer from a repeated-byte seed so the verifier
// can resolve its key offline.
func didKeySigner(t *testing.T, seedByte byte) *signer.Signer {
	t.Helper()
	seed := filled(seedByte)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	did, err := signer.DIDKeyFromEd25519(pub)
	if err != nil {
		t.Fatalf("DIDKeyFromEd25519: %v", err)
	}
	s, err := signer.New(signer.Config{DID: did, Ed25519Seed: seed})
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}
	return s
}

// robotScenario is a full valid robot-identity chain whose pieces a test can
// perturb one at a time.
type robotScenario struct {
	root         *signer.Signer
	manufacturer *signer.Signer
	robot        *signer.Signer
	recognized   map[string]any
	robotHWCred  map[string]any
	authority    map[string]any
	robotKeyMB   string
}

func buildRobotScenario(t *testing.T, recognizedActions []string) robotScenario {
	return buildRobotScenarioSeed(t, recognizedActions, 0x11)
}

// buildRobotScenarioSeed builds a scenario from a distinct seed base so two
// scenarios can coexist with different robot, manufacturer, and root keys.
func buildRobotScenarioSeed(t *testing.T, recognizedActions []string, base byte) robotScenario {
	t.Helper()
	root := didKeySigner(t, base)
	manufacturer := didKeySigner(t, base+1)
	robot := didKeySigner(t, base+2)

	if recognizedActions == nil {
		recognizedActions = []string{ActionIssueRobotIdentity}
	}
	recognized, err := signer.BuildRecognizedIssuer(root, signer.RecognizedIssuerOptions{
		IssuerDID:         manufacturer.DID(),
		RecognizedActions: recognizedActions,
	})
	if err != nil {
		t.Fatalf("BuildRecognizedIssuer: %v", err)
	}

	hwRoot, err := NewSoftwareRoot(filled(base+5), "TPM")
	if err != nil {
		t.Fatalf("NewSoftwareRoot: %v", err)
	}
	robotHWCred, err := MintRobotIdentity(robot, hwRoot, MintOptions{
		Make: "Acme Robotics", Model: "AR-7", Serial: "SN-000123",
	})
	if err != nil {
		t.Fatalf("MintRobotIdentity: %v", err)
	}

	robotKeyMB, err := robot.PublicKeyMultikey()
	if err != nil {
		t.Fatalf("PublicKeyMultikey: %v", err)
	}
	authority, err := BuildRobotIdentity(manufacturer, BuildRobotIdentityOptions{
		RobotDID:             robot.DID(),
		HardwareKeyMultibase: robotKeyMB,
		Attributes:           robotAttrs,
	})
	if err != nil {
		t.Fatalf("BuildRobotIdentity: %v", err)
	}

	return robotScenario{
		root:         root,
		manufacturer: manufacturer,
		robot:        robot,
		recognized:   recognized,
		robotHWCred:  robotHWCred,
		authority:    authority,
		robotKeyMB:   robotKeyMB,
	}
}

func (s robotScenario) verify() RobotIdentityChainResult {
	return VerifyRobotIdentityChain(s.authority, s.recognized, s.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    s.root.DID(),
		RobotPublicKey: s.robot.PublicKeyEd25519(),
	})
}

func TestRobotIdentityHappyPath(t *testing.T) {
	s := buildRobotScenario(t, nil)
	r := s.verify()
	if !r.Ok {
		t.Fatalf("expected ok, got reason %q", r.Reason)
	}
	if !r.HardwareRooted {
		t.Fatal("expected HardwareRooted true")
	}
	if r.RobotDID != s.robot.DID() {
		t.Fatalf("robot DID mismatch: %s vs %s", r.RobotDID, s.robot.DID())
	}
	if r.IssuerDID != s.manufacturer.DID() {
		t.Fatalf("issuer DID mismatch: %s vs %s", r.IssuerDID, s.manufacturer.DID())
	}
	if r.RootDID != s.root.DID() {
		t.Fatalf("root DID mismatch: %s vs %s", r.RootDID, s.root.DID())
	}
	if r.Attributes["make"] != "Acme Robotics" {
		t.Fatalf("unexpected make: %v", r.Attributes["make"])
	}
}

func TestRobotIdentityIssuerNotRecognizedForRobotAction(t *testing.T) {
	// The manufacturer is recognized only to issue agent identities.
	s := buildRobotScenario(t, []string{signer.ActionIssueAgentIdentity})
	r := s.verify()
	if r.Ok || r.Reason != "issuer_not_recognized_for_action" {
		t.Fatalf("expected issuer_not_recognized_for_action, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

func TestRobotIdentityWrongPinnedRoot(t *testing.T) {
	s := buildRobotScenario(t, nil)
	other := didKeySigner(t, 0x1F)
	r := VerifyRobotIdentityChain(s.authority, s.recognized, s.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    other.DID(),
		RobotPublicKey: s.robot.PublicKeyEd25519(),
	})
	if r.Ok || r.Reason != "recognized_issuer_not_from_root" {
		t.Fatalf("expected recognized_issuer_not_from_root, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

func TestRobotIdentityManufacturerVouchedDifferentKey(t *testing.T) {
	// The authority identity binds a key that is not the robot's real key.
	s := buildRobotScenario(t, nil)
	stray := didKeySigner(t, 0x1A)
	strayMB, err := stray.PublicKeyMultikey()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := BuildRobotIdentity(s.manufacturer, BuildRobotIdentityOptions{
		RobotDID:             s.robot.DID(),
		HardwareKeyMultibase: strayMB,
		Attributes:           robotAttrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyRobotIdentityChain(forged, s.recognized, s.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    s.root.DID(),
		RobotPublicKey: s.robot.PublicKeyEd25519(),
	})
	if r.Ok || r.Reason != "hardware_key_mismatch" {
		t.Fatalf("expected hardware_key_mismatch, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

func TestRobotIdentityImpostorKey(t *testing.T) {
	// A software key claims to be hardware-rooted: present the robot's own
	// hardware credential but verify it under an impostor key, so the credential
	// proof no longer verifies and the hardware root is invalid.
	s := buildRobotScenario(t, nil)
	impostor := didKeySigner(t, 0x1B)
	r := VerifyRobotIdentityChain(s.authority, s.recognized, s.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    s.root.DID(),
		RobotPublicKey: impostor.PublicKeyEd25519(),
	})
	if r.Ok || r.Reason != "hardware_root_invalid" {
		t.Fatalf("expected hardware_root_invalid, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

func TestRobotIdentityHardwareCredentialForDifferentRobot(t *testing.T) {
	s := buildRobotScenario(t, nil)
	other := buildRobotScenarioSeed(t, nil, 0x30)
	// Present robot B's hardware credential (verified with B's key) against robot
	// A's authority identity: the subjects do not match.
	r := VerifyRobotIdentityChain(s.authority, s.recognized, other.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    s.root.DID(),
		RobotPublicKey: other.robot.PublicKeyEd25519(),
	})
	if r.Ok || r.Reason != "hardware_subject_mismatch" {
		t.Fatalf("expected hardware_subject_mismatch, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

func TestRobotIdentityPlainAgentHasNoHardwareKey(t *testing.T) {
	// A recognized robot-issuer issues a plain agent identity with no hardware key.
	s := buildRobotScenario(t, nil)
	plain, err := signer.BuildAgentIdentity(s.manufacturer, signer.AgentIdentityOptions{
		SubjectDID: s.robot.DID(),
		Attributes: map[string]any{"make": "Acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyRobotIdentityChain(plain, s.recognized, s.robotHWCred, VerifyRobotIdentityChainOptions{
		TrustedRoot:    s.root.DID(),
		RobotPublicKey: s.robot.PublicKeyEd25519(),
	})
	if r.Ok || r.Reason != "identity_no_hardware_key" {
		t.Fatalf("expected identity_no_hardware_key, got ok=%v reason=%q", r.Ok, r.Reason)
	}
}

// robotChainVector is the robot slice of the shared root-of-trust interop vector.
type robotChainVector struct {
	TrustedRoot             string         `json:"trustedRoot"`
	RobotRecognizedIssuer   map[string]any `json:"robotRecognizedIssuer"`
	RobotHardwareCredential map[string]any `json:"robotHardwareCredential"`
	RobotAuthorityIdentity  map[string]any `json:"robotAuthorityIdentity"`
	RobotPublicKey          map[string]any `json:"robotPublicKey"`
	Expected                struct {
		VerifyRobotIdentityChain bool   `json:"verifyRobotIdentityChain"`
		RobotDid                 string `json:"robotDid"`
		RobotIssuerDid           string `json:"robotIssuerDid"`
		HardwareRooted           bool   `json:"hardwareRooted"`
	} `json:"expected"`
}

// TestRobotIdentityInteropVector is the cross-language interop proof: Go verifies
// the robot chain minted by the Python module and pinned in the shared vector.
func TestRobotIdentityInteropVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "root-of-trust", "vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v robotChainVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}

	robotPub := ed25519FromJWK(t, v.RobotPublicKey)
	r := VerifyRobotIdentityChain(
		v.RobotAuthorityIdentity,
		v.RobotRecognizedIssuer,
		v.RobotHardwareCredential,
		VerifyRobotIdentityChainOptions{TrustedRoot: v.TrustedRoot, RobotPublicKey: robotPub},
	)
	if !r.Ok {
		t.Fatalf("expected the Python-minted robot chain to verify in Go, reason %q", r.Reason)
	}
	if !r.HardwareRooted {
		t.Fatal("expected HardwareRooted true")
	}
	if r.RobotDID != v.Expected.RobotDid {
		t.Fatalf("robot DID mismatch\n expected: %s\n got:      %s", v.Expected.RobotDid, r.RobotDID)
	}
	if r.IssuerDID != v.Expected.RobotIssuerDid {
		t.Fatalf("issuer DID mismatch\n expected: %s\n got:      %s", v.Expected.RobotIssuerDid, r.IssuerDID)
	}
}
