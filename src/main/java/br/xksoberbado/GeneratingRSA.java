package br.xksoberbado;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Objects;

public class GeneratingRSA {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static KeyPair keyPair;

    public static void main(final String[] args) {
        final var text = "Igor Rudel";
        System.out.println("Original text: " + text);
        final var encrypted = encrypt(text);
        System.out.println("Encrypted text: " + encrypted);
        System.out.println("Decrypted text: " + decrypt(encrypted));
    }

    @SneakyThrows
    private static String encrypt(final String text) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getKeyPair().getPublic());

        final var bytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(bytes);
    }

    @SneakyThrows
    private static String decrypt(final String encrypted) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getKeyPair().getPrivate());

        final var bytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(bytes, StandardCharsets.UTF_8);
    }

    @SneakyThrows
    public static KeyPair getKeyPair() {
        if (Objects.nonNull(keyPair)) {
            return keyPair;
        }

        final var generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(2048);

        keyPair = generator.generateKeyPair();
        System.out.println("Private Base64: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Base64: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        return keyPair;
    }
}
