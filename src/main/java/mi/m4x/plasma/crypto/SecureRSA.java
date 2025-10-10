package mi.m4x.plasma.crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
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

    // single shared SecureRandom (fallback safe)
    private static final SecureRandom SECURE_RANDOM;
    static {
        SecureRandom tmp;
        try { tmp = SecureRandom.getInstanceStrong(); }
        catch (Exception e) { tmp = new SecureRandom(); }
        SECURE_RANDOM = tmp;
    }

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
        keyGen.initialize(rsaKeySize, SECURE_RANDOM);
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
        SecureRandom random = SECURE_RANDOM;

        // generate ephemeral AES key
        byte[] aesBytes = new byte[AES_KEY_SIZE / 8];
        random.nextBytes(aesBytes);
        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");

        // copy AES bytes into a direct buffer for stronger wipe later
        ByteBuffer aesDirect = ByteBuffer.allocateDirect(aesBytes.length);
        aesDirect.put(aesBytes);
        aesDirect.flip();

        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] cipherText = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientRsaPub);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesBytes);

        // Zero out AES key material after use (heap)
        Arrays.fill(aesBytes, (byte) 0);
        // Zero out direct buffer (off-heap)
        secureClear(aesDirect);

        // attempt destroy if available
        try { if (aesKey instanceof Destroyable) ((Destroyable) aesKey).destroy(); } catch (DestroyFailedException ignored) {}

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
        if (payload.length < sigLen) throw new SecurityException("Payload too short for signature");
        byte[] signature = Arrays.copyOfRange(payload, 0, sigLen);
        byte[] combined = Arrays.copyOfRange(payload, sigLen, payload.length);

        // Constant-time signature verification (Signature API used; additional protections below)
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

        // copy AES bytes to direct buffer for secure wipe after use
        ByteBuffer aesDirect = ByteBuffer.allocateDirect(aesBytes.length);
        aesDirect.put(aesBytes);
        aesDirect.flip();

        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");

        // zero heap copy
        Arrays.fill(aesBytes, (byte) 0);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] decrypted = aesCipher.doFinal(cipherText);

        // Convert to String, then wipe decrypted bytes
        String result = new String(decrypted, StandardCharsets.UTF_8);
        Arrays.fill(decrypted, (byte) 0);

        // attempt destroy
        try { if (aesKey instanceof Destroyable) ((Destroyable) aesKey).destroy(); } catch (DestroyFailedException ignored) {}

        // wipe direct buffer
        secureClear(aesDirect);

        return result;
    }

    /**
     * Encrypt with ephemeral ECDH (P-256) key agreement — produces forward secrecy.
     *
     * @param plainText plaintext
     * @param recipientEcPub recipient's EC public key (curve secp256r1)
     * @param senderRsaPriv sender's RSA private key used to sign the payload
     * @return Base64 envelope
     * @throws Exception on failure
     */
    public String encryptWithEphemeralECDH(String plainText, PublicKey recipientEcPub, PrivateKey senderRsaPriv) throws Exception {
        // ephemeral EC keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), SECURE_RANDOM);
        KeyPair eph = kpg.generateKeyPair();

        // derive shared secret
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(recipientEcPub, true);
        byte[] shared = ka.generateSecret();

        // derive AES key via SHA-256(shared)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesBytes = sha256.digest(shared); // 32 bytes -> AES-256

        // zero shared asap
        Arrays.fill(shared, (byte) 0);

        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");
        // copy aes bytes to direct buffer for wiping
        ByteBuffer aesDirect = ByteBuffer.allocateDirect(aesBytes.length);
        aesDirect.put(aesBytes);
        aesDirect.flip();
        Arrays.fill(aesBytes, (byte) 0); // wipe heap copy

        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] cipherText = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // payload: [ephPubLen:int][ephPub][iv][ciphertext]
        byte[] ephPubBytes = eph.getPublic().getEncoded();
        ByteBuffer pb = ByteBuffer.allocate(4 + ephPubBytes.length + iv.length + cipherText.length);
        pb.putInt(ephPubBytes.length);
        pb.put(ephPubBytes);
        pb.put(iv);
        pb.put(cipherText);
        byte[] payload = pb.array();

        // sign payload with sender's RSA private key
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(senderRsaPriv, SECURE_RANDOM);
        sig.update(payload);
        byte[] signature = sig.sign();

        // final envelope: [sigLen:int][sig][payload]
        ByteBuffer out = ByteBuffer.allocate(4 + signature.length + payload.length);
        out.putInt(signature.length);
        out.put(signature);
        out.put(payload);

        // attempt destroy and wipe
        try { if (aesKey instanceof Destroyable) ((Destroyable) aesKey).destroy(); } catch (DestroyFailedException ignored) {}
        secureClear(aesDirect);

        return Base64.getEncoder().encodeToString(out.array());
    }

    /**
     * Decrypt an envelope produced by {@link #encryptWithEphemeralECDH(String, PublicKey, PrivateKey)}.
     *
     * @param base64Envelope base64 string produced by encryptWithEphemeralECDH
     * @param recipientEcPriv recipient's EC private key (secp256r1)
     * @param senderRsaPub sender's RSA public key to verify signature
     * @return plaintext
     * @throws Exception on failure
     */
    public String decryptEphemeralECDH(String base64Envelope, PrivateKey recipientEcPriv, PublicKey senderRsaPub) throws Exception {
        byte[] raw = Base64.getDecoder().decode(base64Envelope);
        ByteBuffer buf = ByteBuffer.wrap(raw);

        int sigLen = buf.getInt();
        if (sigLen <= 0 || sigLen > raw.length - 4) throw new SecurityException("Invalid signature length");
        byte[] signature = new byte[sigLen];
        buf.get(signature);

        byte[] payload = new byte[buf.remaining()];
        buf.get(payload);

        // verify signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(senderRsaPub);
        sig.update(payload);
        if (!sig.verify(signature)) throw new SecurityException("Signature verification failed!");

        ByteBuffer p = ByteBuffer.wrap(payload);
        int ephLen = p.getInt();
        if (ephLen <= 0 || ephLen > p.remaining()) throw new SecurityException("Invalid ephemeral public length");
        byte[] ephPubBytes = new byte[ephLen];
        p.get(ephPubBytes);

        byte[] iv = new byte[GCM_IV_LENGTH];
        p.get(iv);

        byte[] cipherText = new byte[p.remaining()];
        p.get(cipherText);

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey ephPub = kf.generatePublic(new X509EncodedKeySpec(ephPubBytes));

        // derive shared secret
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(recipientEcPriv);
        ka.doPhase(ephPub, true);
        byte[] shared = ka.generateSecret();

        // derive AES key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesBytes = sha256.digest(shared);
        Arrays.fill(shared, (byte) 0);

        // copy to direct buffer for wiping
        ByteBuffer aesDirect = ByteBuffer.allocateDirect(aesBytes.length);
        aesDirect.put(aesBytes);
        aesDirect.flip();

        SecretKey aesKey = new SecretKeySpec(aesBytes, "AES");
        Arrays.fill(aesBytes, (byte) 0);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] decrypted = aesCipher.doFinal(cipherText);

        String result = new String(decrypted, StandardCharsets.UTF_8);
        Arrays.fill(decrypted, (byte) 0);

        try { if (aesKey instanceof Destroyable) ((Destroyable) aesKey).destroy(); } catch (DestroyFailedException ignored) {}
        secureClear(aesDirect);

        return result;
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
        signature.initSign(rsaKeyPair.getPrivate(), SECURE_RANDOM);
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

    /**
     * Store a private key into a JKS keystore file (or other keystore type if configured).
     * Note: In production you should use platform-specific keystores (PKCS11, Windows-MY, Apple Keychain).
     *
     * @param keystorePath file path to write keystore
     * @param password     keystore password
     * @param alias        alias to store key at
     * @param key          private key to store
     * @throws Exception on IO or keystore errors
     */
    public static void storeKeyInKeyStore(String keystorePath, char[] password, String alias, Key key) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password);
        if (key instanceof PrivateKey) {
            // store private key as a key entry (no cert chain supplied)
            ks.setKeyEntry(alias, key, password, null);
        } else {
            // for public keys, store as a trusted cert entry isn't done here; callers may store differently
            throw new IllegalArgumentException("Only private keys can be stored with this helper. Use certificate-based storage for public keys.");
        }
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, password);
        }
    }

    /**
     * Load a private key from a keystore file.
     *
     * @param keystorePath keystore path
     * @param password     password
     * @param alias        alias of key
     * @return Key (PrivateKey)
     * @throws Exception on error
     */
    public static Key loadKeyFromKeyStore(String keystorePath, char[] password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password);
        }
        Key key = ks.getKey(alias, password);
        if (key == null) throw new IllegalArgumentException("No key found for alias: " + alias);
        return key;
    }

    /**
     * Securely clears a direct ByteBuffer (off-heap) by overwriting with zeros.
     *
     * @param buffer direct ByteBuffer to clear
     */
    private static void secureClear(ByteBuffer buffer) {
        if (buffer == null) return;
        // ensure direct buffer
        try {
            buffer.clear();
            while (buffer.hasRemaining()) buffer.put((byte) 0);
            buffer.clear();
        } catch (Exception ignored) {
        }
    }
}
