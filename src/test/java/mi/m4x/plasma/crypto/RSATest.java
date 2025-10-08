package mi.m4x.plasma.crypto;

public class RSATest {

    public static void main(String[] args) {
        try {
            // Initialize RSA
            RSA rsa = new RSA();

            // Generate keys
            rsa.generateKeys(2048);
            System.out.println("Public Key: " + rsa.getPublicKey());
            System.out.println("Private Key: " + rsa.getPrivateKey());

            // Sample message
            String message = "Testing RSA";

            // Encrypt
            String encrypted = rsa.encrypt(message);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt
            String decrypted = rsa.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);

            // Sign
            String signature = rsa.sign(message);
            System.out.println("Signature: " + signature);

            // Verify
            boolean isValid = rsa.verify(message, signature);
            System.out.println("Signature valid: " + isValid);

            // Load keys (optional test)
            RSA rsa2 = new RSA();
            rsa2.loadKeys(rsa.getPublicKey(), rsa.getPrivateKey());
            String decryptedFromLoaded = rsa2.decrypt(encrypted);
            System.out.println("Decrypted from loaded keys: " + decryptedFromLoaded);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

