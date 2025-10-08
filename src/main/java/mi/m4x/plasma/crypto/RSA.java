package mi.m4x.plasma.crypto;

import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;

/**
 * BasicRSA is a simple RSA utility class for key generation, encryption,
 * decryption, signing, and verification. Designed for API usage.
 * <p>
 * This class uses Java's built-in Security API.
 * Key size: 2048 bits (recommended for general security purposes).
 * </p>
 *
 * @author M4ximumPizza
 * @since 1.0.1
 */
public class RSA {

    private KeyPair keyPair;

    /**
     * Generates a new RSA key pair.
     *
     * @param keySize size of the key in bits (2048 recommended)
     * @throws NoSuchAlgorithmException if RSA algorithm is not available
     */
    public void generateKeys(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        keyPair = keyGen.generateKeyPair();
    }

    /**
     * Returns the public key as a Base64-encoded string.
     *
     * @return Base64-encoded public key
     */
    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /**
     * Returns the private key as a Base64-encoded string.
     *
     * @return Base64-encoded private key
     */
    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    /**
     * Encrypts data using the public key.
     *
     * @param plainText data to encrypt
     * @return Base64-encoded encrypted string
     * @throws Exception if encryption fails
     */
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts data using the private key.
     *
     * @param cipherText Base64-encoded encrypted string
     * @return decrypted plain text
     * @throws Exception if decryption fails
     */
    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }

    /**
     * Signs data using the private key.
     *
     * @param data data to sign
     * @return Base64-encoded signature
     * @throws Exception if signing fails
     */
    public String sign(String data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * Verifies a signature using the public key.
     *
     * @param data data that was signed
     * @param signatureStr Base64-encoded signature
     * @return true if signature is valid, false otherwise
     * @throws Exception if verification fails
     */
    public boolean verify(String data, String signatureStr) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(keyPair.getPublic());
        signature.update(data.getBytes());
        return signature.verify(Base64.getDecoder().decode(signatureStr));
    }

    /**
     * Loads an existing key pair from Base64 strings.
     *
     * @param publicKeyStr  Base64-encoded public key
     * @param privateKeyStr Base64-encoded private key
     * @throws Exception if key reconstruction fails
     */
    public void loadKeys(String publicKeyStr, String privateKeyStr) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] pubBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
        PublicKey pubKey = keyFactory.generatePublic(pubSpec);

        byte[] privBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        keyPair = new KeyPair(pubKey, privKey);
    }
}
