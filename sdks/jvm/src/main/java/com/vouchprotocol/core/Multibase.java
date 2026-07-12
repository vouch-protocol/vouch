package com.vouchprotocol.core;

import java.math.BigInteger;

/**
 * Minimal base58btc / Multikey decoding for did:key issuers.
 *
 * A did:key encodes the public key in the identifier itself:
 * {@code did:key:z<base58btc(0xed 0x01 || ed25519_public_key)>}. This decoder
 * recovers the 32-byte Ed25519 public key so a did:key issuer can be verified
 * offline. Encoding stays in the Rust core; this is only the small read path the
 * JVM needs to resolve a did:key.
 */
final class Multibase {

    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    // Multicodec prefix for an Ed25519 public key (varint 0xed 0x01).
    private static final int MULTICODEC_ED25519_0 = 0xed;
    private static final int MULTICODEC_ED25519_1 = 0x01;
    private static final int ED25519_PUBLIC_KEY_LEN = 32;

    private Multibase() {}

    /** Decode the Ed25519 public key bytes embedded in a did:key. */
    static byte[] decodeEd25519DidKey(String didKey) {
        if (didKey == null || !didKey.startsWith("did:key:")) {
            throw new VouchAgent.VouchAgentException("not a did:key: " + didKey);
        }
        String multikey = didKey.substring("did:key:".length());
        if (multikey.isEmpty() || multikey.charAt(0) != 'z') {
            throw new VouchAgent.VouchAgentException("did:key must use base58btc (z) multibase");
        }
        byte[] decoded = base58Decode(multikey.substring(1));
        if (decoded.length != 2 + ED25519_PUBLIC_KEY_LEN
                || (decoded[0] & 0xff) != MULTICODEC_ED25519_0
                || (decoded[1] & 0xff) != MULTICODEC_ED25519_1) {
            throw new VouchAgent.VouchAgentException("did:key is not an Ed25519 key");
        }
        byte[] pub = new byte[ED25519_PUBLIC_KEY_LEN];
        System.arraycopy(decoded, 2, pub, 0, ED25519_PUBLIC_KEY_LEN);
        return pub;
    }

    private static byte[] base58Decode(String s) {
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int digit = ALPHABET.indexOf(s.charAt(i));
            if (digit < 0) {
                throw new VouchAgent.VouchAgentException("invalid base58 character: " + s.charAt(i));
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = num.toByteArray();
        // BigInteger may prepend a sign byte; drop a leading 0x00.
        int offset = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0;

        // Restore leading zero bytes, one per leading '1' in the input.
        int leadingZeros = 0;
        while (leadingZeros < s.length() && s.charAt(leadingZeros) == '1') {
            leadingZeros++;
        }

        byte[] out = new byte[leadingZeros + (bytes.length - offset)];
        System.arraycopy(bytes, offset, out, leadingZeros, bytes.length - offset);
        return out;
    }
}
