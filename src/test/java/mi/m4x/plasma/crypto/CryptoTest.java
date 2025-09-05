package mi.m4x.plasma.crypto;

import mi.m4x.plasma.crypto.CryptoUtils;

public class CryptoTest {

    public static void main(String[] args) {
        String text = "Hello, World!";

        String sha256Hash = CryptoUtils.sha256(text);
        String sha512Hash = CryptoUtils.sha512(text);
        String random = CryptoUtils.randomToken(3);

        System.out.println("Input Text: " + text);
        System.out.println("SHA-256 Hash: " + sha256Hash);
        System.out.println("SHA-512 Hash: " + sha512Hash);
        System.out.println("Random Token: " + random);
    }
}
