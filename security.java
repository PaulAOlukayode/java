package com.paymentgateway.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class ApiKeyEngine {

    private static final String SECRET_PREFIX = "sk_live_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final class TokenCluster {
        private final String rawSecretKey;
        private final String databaseHash;

        public TokenCluster(String rawSecretKey, String databaseHash) {
            this.rawSecretKey = rawSecretKey;
            this.databaseHash = databaseHash;
        }

        public String getRawSecretKey() { return rawSecretKey; }
        public String getDatabaseHash() { return databaseHash; }
    }

    /**
     * Executes the Core Cryptographic Generation Sequence.
     * Computes random allocations, appends checking codes, and handles secure string hashing.
     */
    public static TokenCluster generateTokenCluster() {
        byte[] secretBytes = new byte[32];
        SECURE_RANDOM.nextBytes(secretBytes);
        String secretComponent = bytesToHex(secretBytes);
        String checksum = computeMd5Checksum(secretComponent);

        String rawSecretKey = SECRET_PREFIX + secretComponent + "_" + checksum;
        String databaseHash = computeSha256(rawSecretKey);

        return new TokenCluster(rawSecretKey, databaseHash);
    }

    /**
     * Inspects token suffixes immediately to reject corrupted inputs without executing database operations.
     */
    public static boolean hasValidStructure(String incomingKey, String targetPrefix) {
        if (incomingKey == null || !incomingKey.startsWith(targetPrefix)) {
            return false;
        }
        String actualBody = incomingKey.substring(targetPrefix.length());
        String[] segments = actualBody.split("_");
        if (segments.length != 2) {
            return false;
        }
        return computeMd5Checksum(segments[0]).equals(segments[1]);
    }

    /**
     * Compares incoming signatures using constant-time evaluation to negate side-channel timing analysis.
     */
    public static boolean verifySecretKey(String incomingKey, String storedDbHash) {
        if (!hasValidStructure(incomingKey, SECRET_PREFIX)) {
            return false;
        }
        String calculatedIncomingHash = computeSha256(incomingKey);
        return MessageDigest.isEqual(
            calculatedIncomingHash.getBytes(StandardCharsets.UTF_8), 
            storedDbHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    public static String computeSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 standard missing from runtime environment", e);
        }
    }

    private static String computeMd5Checksum(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest).substring(0, 4);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 standard missing from runtime environment", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
