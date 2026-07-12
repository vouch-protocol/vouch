package com.vouchprotocol.core;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Cross-device identity by per-device keys and delegation (the OSS path).
 *
 * The private key never travels. Each device mints its OWN key locally (see
 * {@link VouchAgent#create}), and the user's root identity delegates scoped,
 * time-bound, revocable authority to that device's DID via
 * {@link #enrollDevice}. A device signs its own actions with its own key,
 * chained under the root grant, and {@link #verifyDelegatedChain} checks the
 * whole chain. Losing a device means revoking one delegation, not rotating
 * the whole identity, and no key is ever copied between devices.
 *
 * Mirrors {@code vouch.fleet} (Python), {@code fleet.ts} (TypeScript), and
 * {@code go-sidecar/signer/fleet.go} (Go).
 */
public final class VouchFleet {

    private static final int DEFAULT_VALID_SECONDS = 86400;
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 30;

    private VouchFleet() {}

    /**
     * Issue a delegation grant from the root agent to a device's DID. The
     * returned grant authorizes deviceDid to act within the given scope; the
     * device, holding its own key, signs its actions with this grant as the
     * parent of its own credential, chaining back to the root. The root never
     * sees or holds the device's key.
     */
    public static String enrollDevice(VouchAgent root, String deviceDid, String action, String target, String resource) {
        return enrollDevice(root, deviceDid, action, target, resource, DEFAULT_VALID_SECONDS);
    }

    public static String enrollDevice(VouchAgent root, String deviceDid, String action, String target, String resource, int validSeconds) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String validFrom = VouchAgent.iso(now);
        String validUntil = VouchAgent.iso(now.plusSeconds(validSeconds));
        String credentialId = "urn:uuid:" + UUID.randomUUID();
        String unsigned = VouchCredentials.build(
                root.did(), action, target, resource, deviceDid, validFrom, validUntil, credentialId);
        return Vouch.sign(unsigned, root.seedB64(), root.did() + "#key-1", validFrom);
    }

    /** Reports whether an identifier (a device DID or a credential id) has been revoked. */
    public interface RevocationCheck {
        boolean isRevoked(String identifier);
    }

    /** The outcome of verifying a delegated device chain. */
    public static final class ChainResult {
        public final boolean ok;
        public final String reason;
        public final VouchCredentials.Credential leaf;
        public final String rootDid;

        private ChainResult(boolean ok, String reason, VouchCredentials.Credential leaf, String rootDid) {
            this.ok = ok;
            this.reason = reason;
            this.leaf = leaf;
            this.rootDid = rootDid;
        }

        private static ChainResult fail(String reason) {
            return new ChainResult(false, reason, null, null);
        }

        private static ChainResult fail(String reason, VouchCredentials.Credential leaf) {
            return new ChainResult(false, reason, leaf, null);
        }

        private static ChainResult ok(VouchCredentials.Credential leaf, String rootDid) {
            return new ChainResult(true, null, leaf, rootDid);
        }
    }

    /**
     * Verifies a delegation chain from a trusted root down to a leaf action.
     * credentials is ordered root-first: [rootGrant, ...intermediateGrants,
     * leafAction]. Every credential's Data Integrity proof and validity
     * window are checked, each step must be authorized by the step before it
     * (the child's issuer is the parent's delegatee), the resource may only
     * narrow, and the validity windows must nest. trustedRoots maps an
     * accepted root issuer DID to its base64 public key; the first
     * credential's issuer MUST appear there.
     */
    public static ChainResult verifyDelegatedChain(List<String> credentials, Map<String, String> trustedRoots) {
        return verifyDelegatedChain(credentials, trustedRoots, null, DEFAULT_CLOCK_SKEW_SECONDS, null, null, null);
    }

    public static ChainResult verifyDelegatedChain(
            List<String> credentials,
            Map<String, String> trustedRoots,
            RevocationCheck revoked,
            long clockSkewSeconds,
            String requireAction,
            String requireTarget,
            String requireResource) {
        if (credentials == null || credentials.isEmpty()) {
            return ChainResult.fail("empty chain");
        }
        RevocationCheck isRevoked = revoked != null ? revoked : id -> false;

        List<VouchCredentials.Credential> passports = new ArrayList<>(credentials.size());
        for (int index = 0; index < credentials.size(); index++) {
            String credentialJson = credentials.get(index);
            VouchCredentials.Credential passport = new VouchCredentials.Credential(credentialJson);
            String issuer = passport.issuer();
            if (issuer == null || issuer.isEmpty()) {
                return ChainResult.fail("credential " + index + " has no issuer");
            }

            String key = trustedRoots.get(issuer);
            if (index == 0 && key == null) {
                return ChainResult.fail("root issuer \"" + issuer + "\" is not in trusted roots");
            }
            if (key == null) {
                key = VouchAgent.publicKeyForIssuer(issuer);
            }
            if (key == null) {
                return ChainResult.fail("credential " + index + " issuer \"" + issuer + "\" key could not be resolved");
            }

            String result = Vouch.verify(credentialJson, key, VouchAgent.iso(Instant.now()), clockSkewSeconds);
            if (!result.contains("\"valid\":true")) {
                return ChainResult.fail("credential " + index + " failed verification");
            }

            if (isRevoked.isRevoked(issuer)) {
                return ChainResult.fail("credential " + index + " issuer \"" + issuer + "\" is revoked");
            }
            String credId = passport.id();
            if (credId != null && !credId.isEmpty() && isRevoked.isRevoked(credId)) {
                return ChainResult.fail("credential " + index + " (" + credId + ") is revoked");
            }
            passports.add(passport);
        }

        for (int i = 0; i < passports.size() - 1; i++) {
            VouchCredentials.Credential parent = passports.get(i);
            VouchCredentials.Credential child = passports.get(i + 1);

            String delegatee = parent.delegatee();
            if (delegatee == null || delegatee.isEmpty()) {
                return ChainResult.fail("link " + i + " (grant by \"" + parent.issuer() + "\") names no delegatee");
            }
            if (isRevoked.isRevoked(delegatee)) {
                return ChainResult.fail("link " + i + ": delegatee \"" + delegatee + "\" is revoked");
            }
            if (!delegatee.equals(child.issuer())) {
                return ChainResult.fail("link " + i + ": child issuer \"" + child.issuer()
                        + "\" is not the delegatee \"" + delegatee + "\" the parent authorized");
            }

            String parentResource = parent.resource();
            String childResource = child.resource();
            if (parentResource != null && childResource != null && !isSubResource(childResource, parentResource)) {
                return ChainResult.fail("link " + i + ": resource \"" + childResource
                        + "\" is not within the granted \"" + parentResource + "\"");
            }

            if (!windowWithin(child, parent)) {
                return ChainResult.fail("link " + i + ": child validity is outside the grant window");
            }
        }

        VouchCredentials.Credential leaf = passports.get(passports.size() - 1);
        if (requireAction != null && !requireAction.equals(leaf.action())) {
            return ChainResult.fail("leaf intent.action != \"" + requireAction + "\"", leaf);
        }
        if (requireTarget != null && !requireTarget.equals(leaf.target())) {
            return ChainResult.fail("leaf intent.target != \"" + requireTarget + "\"", leaf);
        }
        if (requireResource != null && !requireResource.equals(leaf.resource())) {
            return ChainResult.fail("leaf intent.resource != \"" + requireResource + "\"", leaf);
        }

        return ChainResult.ok(leaf, passports.get(0).issuer());
    }

    private static boolean isSubResource(String child, String parent) {
        if (child.equals(parent)) {
            return true;
        }
        String trimmed = parent.endsWith("/") ? parent.substring(0, parent.length() - 1) : parent;
        return child.startsWith(trimmed + "/");
    }

    private static boolean windowWithin(VouchCredentials.Credential child, VouchCredentials.Credential parent) {
        try {
            Instant cFrom = Instant.parse(child.validFrom());
            Instant cUntil = Instant.parse(child.validUntil());
            Instant pFrom = Instant.parse(parent.validFrom());
            Instant pUntil = Instant.parse(parent.validUntil());
            return !cFrom.isBefore(pFrom) && !cUntil.isAfter(pUntil);
        } catch (DateTimeParseException | NullPointerException e) {
            return false;
        }
    }

    /**
     * A small in-memory record of a root's enrolled and revoked devices. Pass
     * {@link #isRevoked} straight to {@link #verifyDelegatedChain}, or back
     * this with your own store (a database, a BitstringStatusList) by
     * implementing {@link RevocationCheck} yourself; this is only the
     * simplest default.
     */
    public static final class DeviceRegistry {
        private final Set<String> enrolled = new HashSet<>();
        private final Set<String> revoked = new HashSet<>();
        private final Map<String, String> grants = new HashMap<>();

        /** Records a device as enrolled (optionally keeping its grant). */
        public void enroll(String deviceDid, String grant) {
            enrolled.add(deviceDid);
            grants.put(deviceDid, grant);
            revoked.remove(deviceDid);
        }

        /** Revokes a device. Chains issued by or delegated to it stop verifying. */
        public void revoke(String deviceDid) {
            revoked.add(deviceDid);
        }

        public boolean isRevoked(String identifier) {
            return revoked.contains(identifier);
        }

        /** Enrolled devices that have not been revoked. */
        public List<String> activeDevices() {
            List<String> active = new ArrayList<>();
            for (String did : enrolled) {
                if (!revoked.contains(did)) {
                    active.add(did);
                }
            }
            return active;
        }
    }
}
