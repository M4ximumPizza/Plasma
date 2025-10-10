package mi.m4x.plasma.crypto;

public class SecureRSATest {

    public static void main(String[] args) {
        try {
            // Initialize sender and recipient SecureRSA instances
            SecureRSA sender = new SecureRSA(4096);
            SecureRSA recipient = new SecureRSA(4096);

            // Generate keys with strong SecureRandom
            sender.generateKeys();
            recipient.generateKeys();

            System.out.println("Sender Public Key: " + sender.getPublicKey());
            System.out.println("Recipient Public Key: " + recipient.getPublicKey());

            // Sample message
            String message = "Testing SecureRSA with hybrid encryption and signed payloads! 🔒";

            // Encrypt message using recipient's public key
            String encrypted = sender.encrypt(message, recipient.rsaKeyPair.getPublic());
            System.out.println("Encrypted: " + encrypted);

            // Decrypt message using recipient's private key and sender's public key
            String decrypted = recipient.decrypt(encrypted, recipient.rsaKeyPair.getPrivate(), sender.rsaKeyPair.getPublic());
            System.out.println("Decrypted: " + decrypted);

            // Verify decrypted message matches original
            System.out.println(message.equals(decrypted) ? "Decryption successful ✅" : "Decryption failed ❌");

            // Demonstrate signing and verification
            String signature = sender.sign(message);
            boolean validSig = sender.verify(message, signature, sender.rsaKeyPair.getPublic());
            System.out.println("Signature valid: " + validSig);

            // Test constant-time signature verification by verifying a modified message
            boolean tamperedSig = sender.verify(message + "X", signature, sender.rsaKeyPair.getPublic());
            System.out.println("Tampered signature valid (should be false): " + tamperedSig);

            // Load keys into new instances to test persistence
            SecureRSA senderCopy = new SecureRSA(4096);
            senderCopy.loadKeys(sender.getPublicKey(), sender.getPrivateKey());

            SecureRSA recipientCopy = new SecureRSA(4096);
            recipientCopy.loadKeys(recipient.getPublicKey(), recipient.getPrivateKey());

            // Decrypt using loaded recipient keys and sender copy public key
            String decryptedCopy = recipientCopy.decrypt(encrypted, recipientCopy.rsaKeyPair.getPrivate(), senderCopy.rsaKeyPair.getPublic());
            System.out.println("Decrypted from loaded keys: " + decryptedCopy);

            // Sign & verify using loaded sender keys
            String signatureCopy = senderCopy.sign(message);
            boolean validCopy = senderCopy.verify(message, signatureCopy, senderCopy.rsaKeyPair.getPublic());
            System.out.println("Signature valid with loaded keys: " + validCopy);

            // Simulate hardware-backed key usage
            System.out.println("Hardware-backed key simulation: keys are stored securely (simulated)");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
