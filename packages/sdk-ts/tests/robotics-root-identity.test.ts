/**
 * Root of Trust for robot identity (TypeScript). Mirrors
 * tests/test_robot_root_identity.py plus a cross-language interop check against
 * the shared vector at test-vectors/root-of-trust/vector.json.
 *
 * The chain anchors a hardware-rooted robot to a recognized manufacturer under
 * one pinned Vouch root. Each adversarial case perturbs exactly one piece of a
 * valid scenario and asserts the reason code the Python module returns.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  Signer,
  buildRecognizedIssuer,
  buildAgentIdentity,
  ACTION_ISSUE_AGENT_IDENTITY,
  ACTION_ISSUE_ROBOT_IDENTITY,
  SoftwareRootOfTrust,
  mintRobotIdentity,
  encodeEd25519Public,
  buildRobotIdentity,
  verifyRobotIdentityChain,
} from '../src';

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../../../test-vectors/root-of-trust/vector.json'),
    'utf8'
  )
);

// Node needs DER-wrapped keys; a raw Ed25519 seed gets this fixed PKCS8 prefix.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const ATTRS = {
  make: 'Acme Robotics',
  model: 'AR-7',
  serial: 'SN-000123',
  owner: 'did:web:acme.example.com',
};

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function privFromSeed(s: Uint8Array): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(s)]),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Build a did:key Signer from a fixed 32-byte Ed25519 seed. */
function signerFromSeed(s: Uint8Array): Signer {
  const priv = privFromSeed(s);
  const pubJwk = crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x: string };
  const xRaw = new Uint8Array(Buffer.from(pubJwk.x, 'base64url'));
  const did = 'did:key:' + encodeEd25519Public(xRaw);
  const jwk = JSON.stringify({
    kty: 'OKP',
    crv: 'Ed25519',
    x: pubJwk.x,
    d: Buffer.from(s).toString('base64url'),
  });
  return new Signer({ privateKey: jwk, did });
}

function pubKeyFromSeed(s: Uint8Array): crypto.KeyObject {
  return crypto.createPublicKey(privFromSeed(s));
}

interface Scenario {
  root: Signer;
  manufacturer: Signer;
  robot: Signer;
  robotPub: crypto.KeyObject;
  robotKeyMb: string;
  recognized: Record<string, unknown>;
  robotHwCred: Record<string, unknown>;
  authority: Record<string, unknown>;
}

/** Build a full valid scenario and return the pieces so tests can perturb one. */
async function buildScenario(
  recognizedActions: string[] = [ACTION_ISSUE_ROBOT_IDENTITY],
  bytes: { root: number; mfr: number; robot: number; hw: number } = {
    root: 0x01,
    mfr: 0x04,
    robot: 0x05,
    hw: 0x06,
  }
): Promise<Scenario> {
  const root = signerFromSeed(seed(bytes.root));
  const manufacturer = signerFromSeed(seed(bytes.mfr));
  const robot = signerFromSeed(seed(bytes.robot));
  const robotPub = pubKeyFromSeed(seed(bytes.robot));

  const recognized = await buildRecognizedIssuer(root, {
    issuerDid: manufacturer.getDid(),
    recognizedActions,
  });
  const hwRoot = new SoftwareRootOfTrust(seed(bytes.hw), 'TPM');
  const robotHwCred = await mintRobotIdentity(robot, hwRoot, {
    make: 'Acme Robotics',
    model: 'AR-7',
    serial: 'SN-000123',
  });
  const robotKeyMb = await robot.getPublicKeyMultikey();
  const authority = await buildRobotIdentity(manufacturer, {
    robotDid: robot.getDid(),
    hardwareKeyMultibase: robotKeyMb,
    attributes: ATTRS,
  });
  return { root, manufacturer, robot, robotPub, robotKeyMb, recognized, robotHwCred, authority };
}

interface Overrides {
  authority?: Record<string, unknown>;
  recognized?: Record<string, unknown>;
  robotHwCred?: Record<string, unknown>;
  trustedRoot?: string;
  robotPublicKey?: crypto.KeyObject;
  isRevoked?: (credential: Record<string, unknown>) => boolean;
}

function verify(s: Scenario, over: Overrides = {}) {
  return verifyRobotIdentityChain(
    over.authority ?? s.authority,
    over.recognized ?? s.recognized,
    over.robotHwCred ?? s.robotHwCred,
    {
      trustedRoot: over.trustedRoot ?? s.root.getDid(),
      robotPublicKey: over.robotPublicKey ?? s.robotPub,
      isRevoked: over.isRevoked,
    }
  );
}

describe('robot identity chain', () => {
  it('happy path confirms provenance and hardware', async () => {
    const s = await buildScenario();
    const r = await verify(s);
    expect(r.ok).toBe(true);
    expect(r.hardwareRooted).toBe(true);
    expect(r.robotDid).toBe(s.robot.getDid());
    expect(r.issuerDid).toBe(s.manufacturer.getDid());
    expect(r.rootDid).toBe(s.root.getDid());
    expect(r.attributes?.make).toBe('Acme Robotics');
  });

  it('rejects an issuer recognized only for agent identities', async () => {
    const s = await buildScenario([ACTION_ISSUE_AGENT_IDENTITY]);
    const r = await verify(s);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('issuer_not_recognized_for_action');
  });

  it('rejects the wrong pinned root', async () => {
    const s = await buildScenario();
    const otherRoot = signerFromSeed(seed(0x09));
    const r = await verify(s, { trustedRoot: otherRoot.getDid() });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('recognized_issuer_not_from_root');
  });

  it('rejects a manufacturer that vouched a different key', async () => {
    const s = await buildScenario();
    const stray = signerFromSeed(seed(0x0a));
    const forgedAuthority = await buildRobotIdentity(s.manufacturer, {
      robotDid: s.robot.getDid(),
      hardwareKeyMultibase: await stray.getPublicKeyMultikey(),
      attributes: ATTRS,
    });
    const r = await verify(s, { authority: forgedAuthority });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('hardware_key_mismatch');
  });

  it('rejects a hardware credential presented under an impostor key', async () => {
    const s = await buildScenario();
    const impostorPub = pubKeyFromSeed(seed(0x0b));
    const r = await verify(s, { robotPublicKey: impostorPub });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('hardware_root_invalid');
  });

  it('rejects a hardware credential for a different robot', async () => {
    const s = await buildScenario();
    const other = await buildScenario(undefined, {
      root: 0x11,
      mfr: 0x14,
      robot: 0x15,
      hw: 0x16,
    });
    const r = await verify(s, {
      robotHwCred: other.robotHwCred,
      robotPublicKey: other.robotPub,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('hardware_subject_mismatch');
  });

  it('rejects a plain agent identity with no hardware key', async () => {
    const s = await buildScenario();
    const plain = await buildAgentIdentity(s.manufacturer, {
      subjectDid: s.robot.getDid(),
      attributes: { make: 'Acme' },
    });
    const r = await verify(s, { authority: plain });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('identity_no_hardware_key');
  });

  it('rejects a self-signed manufacturer not from the root', async () => {
    const s = await buildScenario();
    const rogue = signerFromSeed(seed(0x0c));
    const selfReco = await buildRecognizedIssuer(rogue, {
      issuerDid: s.manufacturer.getDid(),
      recognizedActions: [ACTION_ISSUE_ROBOT_IDENTITY],
    });
    const r = await verify(s, { recognized: selfReco });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('recognized_issuer_not_from_root');
  });

  it('rejects a revoked recognized issuer', async () => {
    const s = await buildScenario();
    const r = await verify(s, { isRevoked: (c) => c === s.recognized });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('recognized_issuer_revoked');
  });
});

describe('robot identity chain: interop vector', () => {
  it('verifies the Python-signed robot chain anchored to the pinned root', async () => {
    const robotPub = crypto.createPublicKey({
      key: VECTOR.robotPublicKey as crypto.JsonWebKey,
      format: 'jwk',
    });
    const r = await verifyRobotIdentityChain(
      VECTOR.robotAuthorityIdentity,
      VECTOR.robotRecognizedIssuer,
      VECTOR.robotHardwareCredential,
      { trustedRoot: VECTOR.trustedRoot, robotPublicKey: robotPub }
    );
    expect(r.ok).toBe(true);
    expect(r.hardwareRooted).toBe(true);
    expect(r.robotDid).toBe(VECTOR.expected.robotDid);
    expect(r.issuerDid).toBe(VECTOR.expected.robotIssuerDid);
    expect(r.rootDid).toBe(VECTOR.trustedRoot);
    expect(VECTOR.expected.verifyRobotIdentityChain).toBe(true);
    expect(VECTOR.expected.hardwareRooted).toBe(true);
  });
});
