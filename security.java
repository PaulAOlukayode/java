package com.aaas.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Core cryptographic engine for API key generation and verification.
 * Zero external dependencies — uses standard JDK providers only.
 */
public final class ApiKeyEngine {

    private static final String SECRET_PREFIX = "sk_live_";
    private static final String PUBLIC_PREFIX = "pk_live_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Holds the generated key pair returned to the caller. */
    public static final class TokenCluster {
        private final String rawSecretKey;   // shown to merchant ONCE, never stored
        private final String rawPublicKey;   // safe to show anytime
        private final String databaseHash;   // SHA-256 of rawSecretKey — stored in DB
        private final String keyPrefix;      // first 16 chars — shown in dashboard

        public TokenCluster(String rawSecretKey, String rawPublicKey,
                            String databaseHash, String keyPrefix) {
            this.rawSecretKey = rawSecretKey;
            this.rawPublicKey = rawPublicKey;
            this.databaseHash = databaseHash;
            this.keyPrefix    = keyPrefix;
        }

        public String getRawSecretKey()  { return rawSecretKey; }
        public String getRawPublicKey()  { return rawPublicKey; }
        public String getDatabaseHash()  { return databaseHash; }
        public String getKeyPrefix()     { return keyPrefix; }
    }

    /**
     * Generates a full API key pair for a new merchant.
     *
     * Steps:
     *   1. SecureRandom generates 32 bytes → hex-encoded (64 chars)
     *   2. Checksum = SHA-256(secretHex).substring(0, 8)
     *   3. Assemble: sk_live_<secretHex>_<checksum>
     *   4. Hash full raw key with SHA-256 → store this in DB
     */
    public static TokenCluster generateTokenCluster() {
        // Step 1: Generate 32 secure random bytes
        byte[] secretBytes = new byte[32];
        SECURE_RANDOM.nextBytes(secretBytes);
        String secretHex = bytesToHex(secretBytes);

        // Step 2: Compute structural checksum (SHA-256, first 8 chars)
        String checksum = computeSha256(secretHex).substring(0, 8);

        // Step 3: Assemble the raw secret key
        String rawSecretKey = SECRET_PREFIX + secretHex + "_" + checksum;

        // Step 4: Generate a public key (separate random bytes)
        byte[] pubBytes = new byte[16];
        SECURE_RANDOM.nextBytes(pubBytes);
        String rawPublicKey = PUBLIC_PREFIX + bytesToHex(pubBytes);

        // Step 5: Hash the raw secret key for DB storage
        String databaseHash = computeSha256(rawSecretKey);

        // Step 6: Prefix for dashboard display (never the full raw key)
        String keyPrefix = rawSecretKey.substring(0, 16); // "sk_live_3f9a2c8b"

        return new TokenCluster(rawSecretKey, rawPublicKey, databaseHash, keyPrefix);
    }

    /**
     * Fast structural validation at the API edge.
     * Rejects malformed keys before any database call is made.
     */
    public static boolean hasValidStructure(String incomingKey, String targetPrefix) {
        if (incomingKey == null || !incomingKey.startsWith(targetPrefix)) return false;

        String body = incomingKey.substring(targetPrefix.length());
        String[] segments = body.split("_");
        if (segments.length != 2) return false;

        // Recompute SHA-256 checksum and compare
        String expectedChecksum = computeSha256(segments[0]).substring(0, 8);
        return expectedChecksum.equals(segments[1]);
    }

    /**
     * Verifies an incoming secret key against the stored DB hash.
     * Uses MessageDigest.isEqual() for constant-time comparison
     * to prevent timing side-channel attacks.
     */
    public static boolean verifySecretKey(String incomingKey, String storedDbHash) {
        if (!hasValidStructure(incomingKey, SECRET_PREFIX)) return false;

        String calculatedHash = computeSha256(incomingKey);
        return MessageDigest.isEqual(
            calculatedHash.getBytes(StandardCharsets.UTF_8),
            storedDbHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    /** Computes a SHA-256 hex digest. */
    public static String computeSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in JDK runtime", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private ApiKeyEngine() { /* static utility — no instantiation */ }
}
