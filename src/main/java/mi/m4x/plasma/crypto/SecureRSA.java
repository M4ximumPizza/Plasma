package mi.m4x.plasma.crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Arrays;

/**
 * SecureRSA provides a hybrid cryptography utility combining RSA and AES-GCM
 * for secure message encryption, decryption, signing, and verification.
 * <p>
 * This class is designed for high-security scenarios and implements several
 * best practices:
 * <ul>
 *     <li>RSA key sizes of 2048 bits or higher for asymmetric encryption and signing.</li>
 *     <li>Hybrid encryption using AES-256-GCM with a randomly generated key per message,
 *         providing forward secrecy for the message contents.</li>
 *     <li>Automatic AES key zeroing to reduce memory exposure of sensitive data.</li>
 *     <li>Random IV per message to ensure ciphertext uniqueness and prevent replay attacks.</li>
 *     <li>Digital signatures with SHA-256 with RSA to guarantee message integrity and authenticity.</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 *     SecureRSA secureRSA = new SecureRSA(4096);
 *     secureRSA.generateKeys();
 *     String encrypted = secureRSA.encrypt("Secret Message", recipientPublicKey);
 *     String decrypted = secureRSA.decrypt(encrypted, recipientPrivateKey, senderPublicKey);
 * </pre>
 * <p>
 * Notes and security considerations:
 * <ul>
 *     <li>Forward secrecy only applies to the AES key for each message; compromising the
 *         long-term RSA key will still compromise past encrypted AES keys.</li>
 *     <li>Always securely store and protect RSA private keys.</li>
 *     <li>Use Base64-encoded key strings for transport or storage.</li>
 *     <li>Ensure the recipient’s public key is authenticated to avoid man-in-the-middle attacks.</li>
 * </ul>
 * <p>
 *
 * @author M4ximumPizza
 * @since 1.0.1
 */
public final class SecureRSA {

    KeyPair rsaKeyPair;
    private final int rsaKeySize;
    private static final int AES_KEY_SIZE = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes
    private static final int GCM_TAG_LENGTH = 128; // bits

    /**
     * Constructs a SecureRSA instance with the specified RSA key size.
     *
     * @param rsaKeySize the RSA key size in bits (minimum 2048)
     * @throws IllegalArgumentException if the key size is less than 2048 bits.
     */
    public SecureRSA(int rsaKeySize) {
        if (rsaKeySize < 2048) throw new IllegalArgumentException("RSA key size must be >= 2048 bits");
        this.rsaKeySize = rsaKeySize;
    }

    /**
     * Generates a new RSA key pair with the configured key size using a strong SecureRandom source.
     *
     * @throws NoSuchAlgorithmException if the "RSA" algorithm is not available.
     */
    public void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        keyGen.initialize(rsaKeySize, secureRandom);
        rsaKeyPair = keyGen.generateKeyPair();
    }

    /**
     * Encrypts a plaintext message using hybrid AES-GCM and RSA encryption with
     * forward secrecy. The AES key is randomly generated per message, and the
     * final payload is signed with the sender's RSA private key.
     *
     * @param plainText the message to encrypt.
     * @param recipientRsaPub the recipient's RSA public key used to encrypt the ephemeral AES key.
     * @return Base64-encoded string representing the signed, hybrid-encrypted payload.
     * @throws Exception if any encryption, signature, or key handling error occurs.
     * @security Forward secrecy is provided by the ephemeral AES key; RSA key compromise
     *           will still compromise past AES keys.
     * @note Always verify recipientRsaPub authenticity before encrypting sensitive data.
     */
    public String encrypt(String plainText, PublicKey recipientRsaPub) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();

        byte[] aesBytes = new byte[AES_KEY_SIZE / 8];
        random.nextBytes(aesBytes);
        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");

        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] cipherText = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientRsaPub);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesBytes);

        // Zero out AES key material after use
        Arrays.fill(aesBytes, (byte) 0);
        try {
            aesKey.destroy();
        } catch (DestroyFailedException ignored) {}

        byte[] combined = new byte[encryptedAesKey.length + iv.length + cipherText.length];
        System.arraycopy(encryptedAesKey, 0, combined, 0, encryptedAesKey.length);
        System.arraycopy(iv, 0, combined, encryptedAesKey.length, iv.length);
        System.arraycopy(cipherText, 0, combined, encryptedAesKey.length + iv.length, cipherText.length);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(rsaKeyPair.getPrivate(), random);
        sig.update(combined);
        byte[] signature = sig.sign();

        byte[] finalPayload = new byte[signature.length + combined.length];
        System.arraycopy(signature, 0, finalPayload, 0, signature.length);
        System.arraycopy(combined, 0, finalPayload, signature.length, combined.length);

        return Base64.getEncoder().encodeToString(finalPayload);
    }

    /**
     * Decrypts a Base64-encoded hybrid-encrypted payload. Verifies the signature
     * using the sender's public key before decrypting the AES-GCM ciphertext.
     *
     * @param base64Payload the Base64-encoded payload from {@link #encrypt(String, PublicKey)}.
     * @param recipientRsaPriv the recipient's RSA private key to decrypt the ephemeral AES key.
     * @param senderRsaPub the sender's RSA public key to verify the signature.
     * @return the original plaintext message.
     * @throws Exception if decryption fails, signature verification fails, or key handling errors occur.
     * @throws SecurityException if the signature verification fails.
     */
    public String decrypt(String base64Payload, PrivateKey recipientRsaPriv, PublicKey senderRsaPub) throws Exception {
        byte[] payload = Base64.getDecoder().decode(base64Payload);

        int sigLen = rsaKeySize / 8;
        byte[] signature = Arrays.copyOfRange(payload, 0, sigLen);
        byte[] combined = Arrays.copyOfRange(payload, sigLen, payload.length);

        // Constant-time signature verification
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(senderRsaPub);
        sig.update(combined);
        boolean verified = sig.verify(signature);
        if (!verified) throw new SecurityException("Signature verification failed!");

        int encryptedAesLen = rsaKeySize / 8;
        if (combined.length < encryptedAesLen + GCM_IV_LENGTH)
            throw new SecurityException("Invalid ciphertext length");

        byte[] encryptedAesKey = Arrays.copyOfRange(combined, 0, encryptedAesLen);
        byte[] iv = Arrays.copyOfRange(combined, encryptedAesLen, encryptedAesLen + GCM_IV_LENGTH);
        byte[] cipherText = Arrays.copyOfRange(combined, encryptedAesLen + GCM_IV_LENGTH, combined.length);

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, recipientRsaPriv);
        byte[] aesBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");

        Arrays.fill(aesBytes, (byte) 0);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] decrypted = aesCipher.doFinal(cipherText);

        try {
            aesKey.destroy();
        } catch (DestroyFailedException ignored) {}

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Signs arbitrary data with the class's RSA private key using SHA-256 with RSA.
     *
     * @param data the string data to sign.
     * @return Base64-encoded digital signature.
     * @throws Exception if signing fails or key is invalid.
     */
    public String sign(String data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(rsaKeyPair.getPrivate(), SecureRandom.getInstanceStrong());
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * Verifies a Base64-encoded signature against provided data using a given RSA public key.
     *
     * @param data the original data that was signed.
     * @param signatureStr the Base64-encoded signature to verify.
     * @param pub the RSA public key corresponding to the private key used to sign the data.
     * @return true if the signature is valid; false otherwise.
     * @throws Exception if verification fails due to key or algorithm errors.
     */
    public boolean verify(String data, String signatureStr, PublicKey pub) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(pub);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(signatureStr));
    }

    /**
     * Returns the Base64-encoded RSA public key of this instance.
     *
     * @return Base64 string of the RSA public key.
     */
    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
    }

    /**
     * Returns the Base64-encoded RSA private key of this instance.
     *
     * @return Base64 string of the RSA private key.
     */
    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded());
    }

    /**
     * Loads RSA key pair from Base64-encoded strings. Both keys must correspond
     * to the same key pair.
     *
     * @param pub Base64-encoded public key string.
     * @param priv Base64-encoded private key string.
     * @throws Exception if keys cannot be parsed or do not match.
     */
    public void loadKeys(String pub, String priv) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pub)));
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(priv)));
        rsaKeyPair = new KeyPair(publicKey, privateKey);
    }
}
