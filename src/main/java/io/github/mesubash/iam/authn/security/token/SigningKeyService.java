package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.entity.SigningKey;
import io.github.mesubash.iam.authn.repository.SigningKeyRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Owns the RS256 signing key pair: bootstrap generation, active-key lookup,
 * rotation, and the public JWKS view. Consumers verify tokens against
 * /.well-known/jwks.json — the private key never leaves this service.
 */
@Slf4j
@Service
@DependsOn("flyway") // bootstrap keygen queries signing_keys — schema must exist first
public class SigningKeyService {

    private static final Duration ROTATED_KEY_GRACE = Duration.ofHours(1); // >= access TTL

    private final SigningKeyRepository repository;
    private final SecretKeySpec keyEncryptionKey; // null = store private key unencrypted (dev)
    private final SecureRandom secureRandom = new SecureRandom();

    private volatile ActiveKey activeKey;
    private final Map<String, RSAPublicKey> publicKeyCache = new ConcurrentHashMap<>();

    public record ActiveKey(String kid, PrivateKey privateKey) {}

    public SigningKeyService(SigningKeyRepository repository,
                             @Value("${iam.authn.keys.encryption-key:}") String encryptionKey) {
        this.repository = repository;
        if (encryptionKey == null || encryptionKey.isBlank()) {
            this.keyEncryptionKey = null;
        } else {
            try {
                byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                        .digest(encryptionKey.getBytes(StandardCharsets.UTF_8));
                this.keyEncryptionKey = new SecretKeySpec(keyBytes, "AES");
            } catch (Exception e) {
                throw new IllegalStateException("Failed to derive key-encryption key", e);
            }
        }
    }

    @PostConstruct
    @Transactional
    public void bootstrap() {
        if (repository.count() == 0) {
            SigningKey key = generateKey();
            repository.save(key);
            log.warn("No signing keys found — generated bootstrap RS256 key pair (kid={}). "
                    + "Private key stored {}.", key.getKid(),
                    keyEncryptionKey != null ? "encrypted" : "UNENCRYPTED — set IAM_KEY_ENCRYPTION_KEY for production");
        }
    }

    public ActiveKey activeKey() {
        ActiveKey cached = activeKey;
        if (cached != null) {
            return cached;
        }
        SigningKey key = repository.findByStatus("ACTIVE")
                .orElseThrow(() -> new IllegalStateException("No ACTIVE signing key"));
        ActiveKey loaded = new ActiveKey(key.getKid(), decodePrivate(decryptIfNeeded(key.getPrivateKey())));
        activeKey = loaded;
        return loaded;
    }

    public RSAPublicKey publicKeyFor(String kid) {
        if (kid == null) {
            return null;
        }
        return publicKeyCache.computeIfAbsent(kid, k ->
                repository.findByKid(k)
                        .filter(sk -> !"REVOKED".equals(sk.getStatus()))
                        .filter(sk -> sk.getNotAfter() == null || sk.getNotAfter().isAfter(Instant.now()))
                        .map(sk -> decodePublic(sk.getPublicKey()))
                        .orElse(null));
    }

    /** RFC 7517 keys array for /.well-known/jwks.json */
    public List<Map<String, String>> jwks() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return repository.findByStatusIn(List.of("ACTIVE", "ROTATED")).stream()
                .filter(k -> k.getNotAfter() == null || k.getNotAfter().isAfter(Instant.now()))
                .map(k -> {
                    RSAPublicKey pub = decodePublic(k.getPublicKey());
                    return Map.of(
                            "kty", "RSA", "use", "sig", "alg", "RS256", "kid", k.getKid(),
                            "n", b64.encodeToString(unsigned(pub.getModulus().toByteArray())),
                            "e", b64.encodeToString(unsigned(pub.getPublicExponent().toByteArray())));
                })
                .toList();
    }

    /** New key signs immediately; old key verifies until the grace window ends. */
    @Transactional
    public String rotate() {
        repository.findByStatus("ACTIVE").ifPresent(old -> {
            old.setStatus("ROTATED");
            old.setRotatedAt(Instant.now());
            old.setNotAfter(Instant.now().plus(ROTATED_KEY_GRACE));
            repository.save(old);
        });
        SigningKey next = repository.save(generateKey());
        activeKey = null;
        publicKeyCache.clear();
        log.warn("Signing key rotated — new kid={}", next.getKid());
        return next.getKid();
    }

    private SigningKey generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();

            byte[] kidBytes = new byte[8];
            secureRandom.nextBytes(kidBytes);

            return SigningKey.builder()
                    .kid(HexFormat.of().formatHex(kidBytes))
                    .publicKey(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))
                    .privateKey(encryptIfNeeded(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())))
                    .status("ACTIVE")
                    .createdAt(Instant.now())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    private static RSAPublicKey decodePublic(String base64Der) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Der)));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid stored public key", e);
        }
    }

    private static PrivateKey decodePrivate(String base64Der) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Der)));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid stored private key", e);
        }
    }

    // leading zero byte from BigInteger two's complement must not leak into JWK values
    private static byte[] unsigned(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private String encryptIfNeeded(String plain) {
        if (keyEncryptionKey == null) {
            return plain;
        }
        try {
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            ByteBuffer buf = ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted);
            return "enc:" + Base64.getEncoder().encodeToString(buf.array());
        } catch (Exception e) {
            throw new IllegalStateException("Private key encryption failed", e);
        }
    }

    private String decryptIfNeeded(String stored) {
        if (!stored.startsWith("enc:")) {
            return stored;
        }
        if (keyEncryptionKey == null) {
            throw new IllegalStateException(
                    "Signing key is encrypted but no key-encryption key is configured");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(stored.substring(4));
            ByteBuffer buf = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[12];
            buf.get(iv);
            byte[] encrypted = new byte[buf.remaining()];
            buf.get(encrypted);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Private key decryption failed", e);
        }
    }
}
