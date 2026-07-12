package com.vouchprotocol.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds the unsigned Vouch Credential body in-language and reads it back.
 *
 * The JSON shape and field order match the canonical {@code build_vouch_credential}
 * in the Rust core and the Python/TypeScript/Go SDKs, so the credential signs and
 * verifies identically across implementations. Only the crypto (signing,
 * verifying) goes through {@link Vouch}; the body is assembled here, the same way
 * the other SDKs assemble it.
 */
public final class VouchCredentials {

    public static final String VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
    public static final String VOUCH_CONTEXT_V1 = "https://vouch-protocol.com/contexts/v1";
    public static final String PROTOCOL_VERSION = "1.0";

    private VouchCredentials() {}

    /**
     * Construct the unsigned credential JSON. The intent fields are required and
     * must be non-empty (Specification 5.4.1).
     */
    public static String build(
            String issuerDid,
            String action,
            String target,
            String resource,
            String validFrom,
            String validUntil,
            String credentialId) {
        return build(issuerDid, action, target, resource, null, validFrom, validUntil, credentialId);
    }

    /**
     * Construct the unsigned credential JSON with an added intent.delegatee
     * field, used to grant another DID scoped authority (cross-device
     * delegation; see {@link VouchFleet}). Pass null to omit it, equivalent to
     * {@link #build(String, String, String, String, String, String, String)}.
     */
    public static String build(
            String issuerDid,
            String action,
            String target,
            String resource,
            String delegatee,
            String validFrom,
            String validUntil,
            String credentialId) {
        requireNonEmpty("action", action);
        requireNonEmpty("target", target);
        requireNonEmpty("resource", resource);

        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"@context\":[")
                .append(str(VC_CONTEXT_V2)).append(',').append(str(VOUCH_CONTEXT_V1))
                .append("],\"id\":").append(str(credentialId))
                .append(",\"type\":[\"VerifiableCredential\",\"VouchCredential\"]")
                .append(",\"issuer\":").append(str(issuerDid))
                .append(",\"validFrom\":").append(str(validFrom))
                .append(",\"validUntil\":").append(str(validUntil))
                .append(",\"credentialSubject\":{\"id\":").append(str(issuerDid))
                .append(",\"vouchVersion\":").append(str(PROTOCOL_VERSION))
                .append(",\"intent\":{\"action\":").append(str(action))
                .append(",\"target\":").append(str(target))
                .append(",\"resource\":").append(str(resource));
        if (delegatee != null && !delegatee.isEmpty()) {
            sb.append(",\"delegatee\":").append(str(delegatee));
        }
        sb.append("}}}");
        return sb.toString();
    }

    private static void requireNonEmpty(String name, String value) {
        if (value == null || value.isEmpty()) {
            throw new VouchAgent.VouchAgentException(
                    "intent." + name + " is required and must be a non-empty string");
        }
    }

    /** Minimal JSON string encoder for the controlled values used in a credential. */
    static String str(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * A read-friendly view over a credential JSON: the intent fields, issuer, and
     * expiry, without re-parsing by hand at the call site.
     */
    public static final class Credential {
        private final String json;

        public Credential(String credentialJson) {
            if (credentialJson == null || credentialJson.isEmpty()) {
                throw new VouchAgent.VouchAgentException("credential JSON is empty");
            }
            this.json = credentialJson;
        }

        public String action() {
            return intentField("action");
        }

        public String target() {
            return intentField("target");
        }

        public String resource() {
            return intentField("resource");
        }

        /** The delegatee DID, if this credential is a delegation grant, else null. */
        public String delegatee() {
            return intentField("delegatee");
        }

        public String issuer() {
            return optional("issuer");
        }

        public String id() {
            return optional("id");
        }

        public String validFrom() {
            return optional("validFrom");
        }

        public String validUntil() {
            return optional("validUntil");
        }

        public String toJson() {
            return json;
        }

        private String intentField(String key) {
            int idx = json.indexOf("\"intent\"");
            String scope = idx >= 0 ? json.substring(idx) : json;
            Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
            return m.find() ? m.group(1) : null;
        }

        private String optional(String key) {
            Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
            return m.find() ? m.group(1) : null;
        }
    }
}
