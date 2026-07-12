package com.vouchprotocol.core;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ergonomic developer-experience layer over {@link Vouch}.
 *
 * Mirrors the Agent helper in the Python and TypeScript SDKs: one object that
 * holds an identity and signs and verifies, so callers do not build credential
 * JSON or pass seeds and public keys around by hand. The credential it produces
 * is the same wire format every Vouch SDK uses; this class only adds ergonomics
 * over the existing core calls in {@link Vouch}.
 *
 * <pre>
 *   VouchAgent agent = VouchAgent.create("agent.example");
 *   String signed = agent.sign("read", "did:web:files", "https://files/x");
 *   boolean ok = agent.verify(signed);
 *   agent.did();
 * </pre>
 *
 * With a domain the identity is {@code did:web:<domain>}; without one it is a
 * self-certifying {@code did:key}. The credential body is built in-language, the
 * same way the Python, TypeScript, and Go SDKs build it, and signed through the
 * core.
 */
public final class VouchAgent {

    private static final int DEFAULT_EXPIRY_SECONDS = 300;

    private final String did;
    private final String seedB64;
    private final String publicB64;
    private final int defaultExpirySeconds;

    private VouchAgent(String did, String seedB64, String publicB64, int defaultExpirySeconds) {
        this.did = did;
        this.seedB64 = seedB64;
        this.publicB64 = publicB64;
        this.defaultExpirySeconds = defaultExpirySeconds;
    }

    /** Mint a fresh identity. With a domain it is did:web, without one did:key. */
    public static VouchAgent create(String domain) {
        return create(domain, DEFAULT_EXPIRY_SECONDS);
    }

    public static VouchAgent create(String domain, int defaultExpirySeconds) {
        String kp = Vouch.generateEd25519();
        String seed = jsonString(kp, "seed_b64");
        String pub = jsonString(kp, "public_b64");
        String did = (domain != null && !domain.isEmpty())
                ? "did:web:" + domain
                : jsonString(kp, "did_key");
        return new VouchAgent(did, seed, pub, defaultExpirySeconds);
    }

    /** Rehydrate an agent from stored key material (no new identity is minted). */
    public static VouchAgent load(String did, String seedB64, String publicB64) {
        return new VouchAgent(did, seedB64, publicB64, DEFAULT_EXPIRY_SECONDS);
    }

    public String did() {
        return did;
    }

    public String publicKeyB64() {
        return publicB64;
    }

    /** Package-private: the raw seed, for same-package ergonomic layers (e.g. VouchFleet). */
    String seedB64() {
        return seedB64;
    }

    /** Sign an intent as a Vouch Credential, returning the signed credential JSON. */
    public String sign(String action, String target, String resource) {
        return sign(action, target, resource, defaultExpirySeconds);
    }

    public String sign(String action, String target, String resource, int validSeconds) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String validFrom = iso(now);
        String validUntil = iso(now.plusSeconds(validSeconds));
        String credentialId = "urn:uuid:" + UUID.randomUUID();
        String unsigned = VouchCredentials.build(
                did, action, target, resource, validFrom, validUntil, credentialId);
        return Vouch.sign(unsigned, seedB64, did + "#key-1", validFrom);
    }

    /**
     * Verify a credential. If it was issued by this agent, it is checked against
     * this agent's own key; otherwise the issuer key is resolved from a did:key
     * issuer. Returns true only when the proof and the validity window are valid.
     */
    public boolean verify(String credentialJson) {
        String issuer = jsonString(credentialJson, "issuer");
        String pub = did.equals(issuer) ? publicB64 : publicKeyForIssuer(issuer);
        if (pub == null) {
            return false;
        }
        return verifyWith(credentialJson, pub);
    }

    /** Verify a credential against an explicit public key (base64). */
    public static boolean verifyWith(String credentialJson, String publicB64) {
        String result = Vouch.verify(
                credentialJson, publicB64, iso(Instant.now()), 30);
        return result.contains("\"valid\":true");
    }

    /**
     * Resolve the Ed25519 public key (base64) for a did:key issuer. Returns null
     * for non-did:key issuers, which need an explicit key or DID-document lookup.
     */
    public static String publicKeyForIssuer(String issuer) {
        if (issuer == null || !issuer.startsWith("did:key:")) {
            return null;
        }
        try {
            byte[] pub = Multibase.decodeEd25519DidKey(issuer);
            return Base64.getEncoder().encodeToString(pub);
        } catch (RuntimeException e) {
            return null;
        }
    }

    // -- internal helpers -----------------------------------------------------

    static String iso(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS).toString().replace("Z", "") + "Z";
    }

    /** Read a top-level-ish string field from a JSON document. */
    static String jsonString(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"")
                .matcher(json);
        if (!m.find()) {
            throw new VouchAgentException("field not found: " + key);
        }
        return m.group(1);
    }

    /** Thrown when the ergonomic layer cannot parse or build a value. */
    public static final class VouchAgentException extends RuntimeException {
        public VouchAgentException(String message) {
            super(message);
        }
    }
}
