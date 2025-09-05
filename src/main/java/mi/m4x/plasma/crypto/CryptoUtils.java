package mi.m4x.plasma.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class providing common cryptographic helpers for hashing,
 * generating random tokens, and computing HMACs.
 *
 * <p>⚠️ Note: This class is intended for utility usage and does not
 * implement advanced security practices like salting, key stretching,
 * or secure key management.</p>
 *
 * @author M4ximumpizza
 * @since 1.0.0
 */
public class CryptoUtils {

    /**
     * Hashes a string using SHA-256 and returns the hash as a hex string.
     *
     * @param input the text to be hashed
     * @return hex-encoded SHA-256 hash of the input
     */
    public static String sha256(String input) {
        return hash("SHA-256", input);
    }

    /**
     * Hashes a string using SHA-512 and returns the hash as a hex string.
     *
     * @param input the text to be hashed
     * @return hex-encoded SHA-512 hash of the input
     */
    public static String sha512(String input) {
        return hash("SHA-512", input);
    }

    /**
     * Performs a hash operation using the specified algorithm.
     *
     * @param algorithm the hashing algorithm (e.g., "SHA-256", "SHA-512")
     * @param input the text to hash
     * @return hex-encoded hash value
     * @throws RuntimeException if the algorithm is not available
     */
    private static String hash(String algorithm, String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    /**
     * Generates a secure random token encoded in Base64 (URL-safe, no padding).
     *
     * @param bytesLength number of random bytes to generate
     * @return random token string in Base64 URL-safe format
     */
    public static String randomToken(int bytesLength) {
        byte[] bytes = new byte[bytesLength];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Computes an HMAC using SHA-256.
     *
     * @param key the secret key for HMAC
     * @param message the message to authenticate
     * @return hex-encoded HMAC-SHA256 of the message
     */
    public static String hmacSha256(String key, String message) {
        return hmac("HmacSHA256", key, message);
    }

    /**
     * Computes an HMAC using SHA-512.
     *
     * @param key the secret key for HMAC
     * @param message the message to authenticate
     * @return hex-encoded HMAC-SHA512 of the message
     */
    public static String hmacSha512(String key, String message) {
        return hmac("HmacSHA512", key, message);
    }

    /**
     * Performs an HMAC computation with the given algorithm.
     *
     * @param algorithm the HMAC algorithm (e.g., "HmacSHA256", "HmacSHA512")
     * @param key the secret key
     * @param message the message to authenticate
     * @return hex-encoded HMAC value
     * @throws RuntimeException if HMAC computation fails
     */
    private static String hmac(String algorithm, String key, String message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm));
            byte[] result = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(result);
        } catch (Exception e) {
            throw new RuntimeException("HMAC failed", e);
        }
    }

    /**
     * Converts a byte array into a lowercase hex string.
     *
     * @param bytes the byte array to convert
     * @return hex string representation of the input bytes
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b)); // format each byte as two-digit hex
        }
        return sb.toString();
    }
}
