package io.github.mesubash.iam.authn.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Component
public class TokenEncryptionUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final SecretKey secretKey;
    private final SecureRandom secureRandom;

    public TokenEncryptionUtil(
            @Value("${iam.authn.cookie.encryption-key:}") String cookieKey,
            @Value("${app.jwt.secret:}") String legacySecret) {
        String keySource = cookieKey;
        if (keySource == null || keySource.isBlank()) {
            if (legacySecret == null || legacySecret.isBlank()) {
                throw new IllegalStateException(
                        "No cookie encryption key configured — set IAM_COOKIE_KEY");
            }
            log.warn("Cookie encryption key derived from app.jwt.secret — "
                    + "set IAM_COOKIE_KEY for an independent key in production");
            keySource = legacySecret;
        }
        try {
            byte[] keyBytes = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(keySource.getBytes(StandardCharsets.UTF_8));
            this.secretKey = new SecretKeySpec(keyBytes, "AES");
            this.secureRandom = new SecureRandom();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize token encryption", e);
        }
    }

    public String encrypt(String plainToken) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] encrypted = cipher.doFinal(plainToken.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            log.error("Failed to encrypt token", e);
            throw new RuntimeException("Token encryption failed", e);
        }
    }

    public String decrypt(String encryptedToken) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encryptedToken);

            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to decrypt token", e);
            throw new RuntimeException("Token decryption failed", e);
        }
    }

    public boolean isValid(String encryptedToken) {
        try {
            decrypt(encryptedToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
