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

public class Main {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final String PUBLIC_KEY_BASE_64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmaqZU1zVTTdOl1p1uP/QV8pxUVWQ9vqnHuA+LzYf9lJS4TWYM/v/KiapESsUgyE1UgKagE+r5yVRgC/RaJ6bFJcBYei3rpyzxFH8AoOIH35dMxtCkkEMgwU+EDYoTiX+FsCPY9ClGdlg/+UURuJeroiJoH4ntlagHc3W8Wua557SmjDBn/SKYJLCORPsADiTSFvFfVCkkOeIcspivjQzLEqciua6gLWfcHx5mMzYw0C//IIE2tNXamGEHVR0CLKIi/5Vkt91DvLB9KpvC1xtJThkbwWX4Gk5jh7geKGKg+JSQ11OJOKipss3b2Xkf2PsE2HxNnIcqYpXNmGyPL6GDwIDAQAB";
    private static final String PRIVATE_KEY_BASE_64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZqplTXNVNN06XWnW4/9BXynFRVZD2+qce4D4vNh/2UlLhNZgz+/8qJqkRKxSDITVSApqAT6vnJVGAL9FonpsUlwFh6LeunLPEUfwCg4gffl0zG0KSQQyDBT4QNihOJf4WwI9j0KUZ2WD/5RRG4l6uiImgfie2VqAdzdbxa5rnntKaMMGf9IpgksI5E+wAOJNIW8V9UKSQ54hyymK+NDMsSpyK5rqAtZ9wfHmYzNjDQL/8ggTa01dqYYQdVHQIsoiL/lWS33UO8sH0qm8LXG0lOGRvBZfgaTmOHuB4oYqD4lJDXU4k4qKmyzdvZeR/Y+wTYfE2chypilc2YbI8voYPAgMBAAECggEAMrbP5WhE6TfwkxkCsyySGPcyENK5hhlRIGqHe1NUlxmySqtCcR2gp8ucjpL2MRS7oTZEwUYKCL4TOMgPR4TYz6HKjgKc5F7JIWihUD8SpLoyjhRYEyaut2r6gaUuBiSZx+6DJEEOzAom7i0vVPmOn/Fl4nbgKlhKfauaXZDSzc/jJAP78Jtsnzlu+X1BY9To0rPbIlF1D/iNY8p4CfU7nPnvtUSKkMHuoG8jUWXVZBsjIO/3t8VBuurBe5mMHC81gr/dW4pqvvrJhCGMYXLOYBF4nhy2jCHLqfF2z0mKjC+XqXwU+xHBj6J+E+NIHH64gR0qrIOJQRoJoLgX0wxTyQKBgQDp5nsInr0VeVsWu7ApiA4gkl0xKMtUfQy8TG/FrWMFcy60OkrmKMulWlvIPm7rtXJKN1TZFyFyuuVti75wec7B5+1yDw+kj48f6DPU+gqGp11HVfxsfVRWoPf2X0IM4L8ZgRgm65YDao0QXzuelZN+pGDmCVUdDa4Aar9mSy91kwKBgQCoL3EG/CJ7CdM9STzbNJ1L58fB1l23jeZbX2qzXA4adqfJ4dhHFuq0yFUtJptAJ6lsK52UxrOXfUJM3i0XbxUuz0ZNm46wiSvVGSCDSJFnAgqvpM2CKIZoVSQo2zfdrW7nE/cHxh1moZHfKsGbkqTxMYgwbYKf8WteNSelX9s7FQKBgDiDyviDOlak8uBkSyVNzXQLSV8mZzKr4Fbi9SLDSSi48vDzIMPJ2aLDWWfhxfVH6yyJgAPQNfG9vM+iM0qD8/QgMNwdTX9KfJ+OAHAWVlLAv6YL3ajtA2LHFALAc3ofF6125roItD9xEFKDYClqJLA10X/jg2A4vPE22bZCtl3nAoGAJiXEnFH6PDApUsBW5l2TxBDJlWTbEvRDqLwGxrH9nPEG89qfJNjE2caK01frZOzaF+f4sTM0rwrBTBAk6CjRBDINfzLmdZJXd9lgL4b5PAURiW93EavBeM6/CelXTZe2DQHRSVkdeBbzsEvRaEkl0nNqsZlVRJQMx2yFFpScdFUCgYEAmoNgKBqrOdvpe+ciAdeQGP8jj9U2kFhllkEILbI9cDoXpxdOoWbuQ3eY62uM4hEQOEqqPepWuh8Sfwizrozq7NluHLnJ/tsfSiVc8nbHbCnhmxMpzeMUHtMmcceSK048pw+xynu7V84vCuiXIuA1Wrswcmrs7LLe6hs5R1dgILE=";

    public static void main(final String[] args) {
        final var encryptedData = "HWl+mJzUb6dL2VcU+hOJk1PIfqKxX8Wqvdy9adheckp4CWUcp8Sf6TG0Ds9FIAIeKgweZWR9Djtmj5kxgnigaTH8tbUI2bxJkt1m2oFVCLDIL7shXsZDxfmXsBBxObAxZZt+UsNrGtQXFfZNBc5WFiW9tWknQyzosQBXU0y1f81spK/KjtBprWtRe1k2Evgvlti4YI2oKEL0dnCuKnWeVxOp/BkflzZMS/PkMxJnNEjhvqnllyapBaU6bFubgbhGFDkBlHqyb5jzuPkb0Oy4LakowNaEpMihrBCmEOAcbuWLH/vKuF8WAl3og6r1+2vQ9Aem1EMmhd3A4Vbtc2UvSw==";
        final var decoded64 = Base64.getDecoder().decode(encryptedData.getBytes());
        System.out.println(decrypt(decoded64));

        final var newData = "123123123";
        System.out.println(encrypt(newData.getBytes()));
    }

    @SneakyThrows
    private static String encrypt(final byte[] data) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());

        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
    }

    @SneakyThrows
    private static String decrypt(final byte[] data) {
        final var cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());

        return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
    }

    @SneakyThrows
    private static PrivateKey getPrivateKey() {
        final var key = Base64.getDecoder().decode(PRIVATE_KEY_BASE_64);
        final var keyFactory = KeyFactory.getInstance(ALGORITHM);

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
    }

    @SneakyThrows
    private static PublicKey getPublicKey() {
        final var key = Base64.getDecoder().decode(PUBLIC_KEY_BASE_64);
        final var keyFactory = KeyFactory.getInstance(ALGORITHM);

        return keyFactory.generatePublic(new X509EncodedKeySpec(key));
    }
}