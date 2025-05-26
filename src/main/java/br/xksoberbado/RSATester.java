package br.xksoberbado;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSATester {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMLCYyWht1rYUZKXNqOyTb8Y06Ooe9oh5rVXRb36qhVB6d5zNykNaP++GoS0L1l9FkUh8cokinq8cQMX9jNSpTiNtQnZQAWbv4z1xNjM4rYdIbYcBzRRlJS/gU67hEy1vTqXvl1TGgSSNwc0uL+LAEVatxqsZjGZVlVIk+64zqrwqINcpOtc+b8hswhJxQzSGFC6mZ0/GDlyhuYccOtcY4tx3imyi2JWW5eDx/mTZgzxB5qXOglWVpihMH7ewbsfVevI/+G4eOprLqALYyOzPOBxhDJAPiy+s5hqkZzAgXwOl4eFiFAYRKuiBLLKISxti3evPxC+c0GS+JPIGF1i5dAgMBAAECggEAAs7oGfPUsMRw5oiPvQ6KvgRAvszJBRWocEU5lKBIQDXmHy33aK/bCLzFH9gkbyFUqutwPafmrO0rm0HSTZcQv4/XpXwTL70jf/ZGLmsQa8tVPG9zn/aeeo2+t0hnQzQP8JcIDHS46LMRjsNZY0Bsov2JBwFBLe2sYccYv5414GJzYPH038VenALnrldjdm8Ag6nKGKCA7ZyCP7zK2Ae7J01gUrFWjCk9Pia/cJ2C8L4rZD9UGbeW1aganxYZSgMi5voGKF9ktj4L6iiw6+yzOy6tIUvQaAIKkiz7rmo14GQxJMCYcV2uoeV+bfLvOvr3kY49PFPnWa4y6DseL42kVwKBgQD2QKO7k71Rn8Yi6BoLuDInb5mhOMyABK8fPCHcbEkSP9UQ0R2d1zdhqWedNuyJQA7e6zZlVBeznrKaQaBNdIFk1gzK+QTHovGFYRYzC2cIhRwLXGZPWFAHLkszV9VQyPxqiTEq0n2l3rYL40rVwsn9VV4nQ/s/btOxIBht/VCLowKBgQDUQRkmmWO1z9nM8RELXECnZ+MONjuhy2+5Zl1kBG9V/14pgBagqV2xniHN2Ntg4RPo1l4zAx0ReBymZ+Nf6MNgxudKyYzycnGhtbghkJwmq8NybRoJvWLtkt2S+VyM7I/HM9+hh0/H+f4tlPKRVEgxgZZ5qh71rcaf0EOzjqn9/wKBgAUPsQ3S7Io38XeYM6jYAVfkKFEy/KkI75yBvORt6VaRr0xoL+alnMLKG5IUpenwQh380aJlhxMvCNa40JWm9l3fNGYbliiQRcyLAUzNSDHZoojtPkEVPJfZMLx+aqj9aIq8BSGvL9vv5uf5pPkdxs8JKSU/dXOJUJqMYVQpZ7VnAoGBANExl+hDJdL7mF40+eeIdPCJo29OZFeCegrwqPr6pADOP7AHXkXap0133TlUkmNZcpX5Mb51QyEEkLgxjBfrASVQ5IUBQLlzsir/PwtVy5ERmQAeJ5uR3P7p0RgaTO1X+h0LM02wXyFpcurZ8njp6H1iizw+P2VEcI7yZMeDxGdhAoGAO+z7cinY31jRHO51LEa5R9jQdTXRawV3j/ch8J+38EMg6HCdqQXmby8MB6LhfIEjHAOPSrZY8jVGzumeCKxWMEtLLdDuirztIN4E4VJjIXQihcfOsviZAGwFluRULlur2ZyT+6p5rHgNF82MDkSIjDyGCUS54dtmwv2DzucAy3o=";
    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzCwmMlobda2FGSlzajsk2/GNOjqHvaIea1V0W9+qoVQeneczcpDWj/vhqEtC9ZfRZFIfHKJIp6vHEDF/YzUqU4jbUJ2UAFm7+M9cTYzOK2HSG2HAc0UZSUv4FOu4RMtb06l75dUxoEkjcHNLi/iwBFWrcarGYxmVZVSJPuuM6q8KiDXKTrXPm/IbMIScUM0hhQupmdPxg5cobmHHDrXGOLcd4psotiVluXg8f5k2YM8QealzoJVlaYoTB+3sG7H1XryP/huHjqay6gC2MjszzgcYQyQD4svrOYapGcwIF8DpeHhYhQGESrogSyyiEsbYt3rz8QvnNBkviTyBhdYuXQIDAQAB";
    private static final String ENCRYPTED_DATA = "WIQs/P0aVfb8Z+cmTM57ltZoIMiTmCfuyS4LNEbRgdCiJaAnRAUwnZpiu8XQI8x6B+7E9e5qbJyB1AhvBTyVzVtcVEjkdhhPlDfe+krfdNhC/DwCcoyT8Iwg48Yb+S5UDp0vTLCYXAJW5nMmg+8tXkHMd3PPDDUXX0RWi+ckaYng7lXazmybwLzGpZBViPAewz/AnWn2kWG1m38TwZuqdWrkJfUNF3MKpEAslyseDAGuL+vpEtOGMoM6a6Z/UtkARklfhfYA4EPiDx0fZHGIKHdUaauDw/EuZaJ+bBcd89Y9h7D8Q06amDTO1h1Jr09e52TCCP5XB4luljx0ni7WjQ==";

    public static void main(final String[] args) {
        final var decrypted = decrypt(ENCRYPTED_DATA);
        System.out.println("Decrypted text: " + decrypted);
        System.out.println("ReDecrypted text: " + decrypt(encrypt(decrypted)));
    }

    @SneakyThrows
    private static String encrypt(final String text) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());

        final var bytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(bytes);
    }

    @SneakyThrows
    private static String decrypt(final String text) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());

        final var bytes = cipher.doFinal(Base64.getDecoder().decode(text.getBytes()));

        return new String(bytes, StandardCharsets.UTF_8);
    }

    @SneakyThrows
    private static PrivateKey getPrivateKey() {
        final var key = Base64.getDecoder().decode(PRIVATE_KEY);
        final var keyFactory = KeyFactory.getInstance(ALGORITHM);

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
    }

    @SneakyThrows
    private static PublicKey getPublicKey() {
        final var key = Base64.getDecoder().decode(PUBLIC_KEY);
        final var keyFactory = KeyFactory.getInstance(ALGORITHM);

        return keyFactory.generatePublic(new X509EncodedKeySpec(key));
    }
}