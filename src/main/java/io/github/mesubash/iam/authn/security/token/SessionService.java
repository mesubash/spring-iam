package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.entity.RefreshToken;
import io.github.mesubash.iam.authn.entity.Session;
import io.github.mesubash.iam.authn.repository.RefreshTokenRepository;
import io.github.mesubash.iam.authn.repository.SessionRepository;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.shared.exception.InvalidTokenException;
import io.github.mesubash.iam.shared.exception.TokenReuseException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Session + refresh-token lifecycle: opaque tokens (SHA-256 at rest),
 * rotation on every use, a retry-grace window for lost responses, and
 * whole-session revocation on replay outside the grace.
 */
@Slf4j
@Service
public class SessionService {

    private static final String RETRY_PREFIX = "authn:rt:retry:";

    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistService blacklistService;
    private final TokenEncryptionUtil encryptionUtil;
    private final StringRedisTemplate redisTemplate;
    private final JwtConfig jwtConfig;
    private final Duration rotationGrace;
    private final int maxSessionsPerIdentity;
    private final SecureRandom secureRandom = new SecureRandom();

    public SessionService(SessionRepository sessionRepository,
                          RefreshTokenRepository refreshTokenRepository,
                          TokenBlacklistService blacklistService,
                          TokenEncryptionUtil encryptionUtil,
                          StringRedisTemplate redisTemplate,
                          JwtConfig jwtConfig,
                          @Value("${iam.authn.session.rotation-grace-seconds:60}") long rotationGraceSeconds,
                          @Value("${iam.authn.session.max-per-identity:10}") int maxSessionsPerIdentity) {
        this.sessionRepository = sessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.blacklistService = blacklistService;
        this.encryptionUtil = encryptionUtil;
        this.redisTemplate = redisTemplate;
        this.jwtConfig = jwtConfig;
        this.rotationGrace = Duration.ofSeconds(rotationGraceSeconds);
        this.maxSessionsPerIdentity = maxSessionsPerIdentity;
    }

    public record IssuedRefresh(Session session, String rawToken) {}

    public record RotationResult(Session session, String rawToken, boolean retried) {}

    @Transactional
    public IssuedRefresh createSession(UUID identityId, String ipAddress, String userAgent) {
        evictBeyondCap(identityId);

        Instant now = Instant.now();
        Session session = sessionRepository.save(Session.builder()
                .identityId(identityId)
                .createdIp(ipAddress)
                .userAgent(userAgent)
                .deviceLabel(deviceLabel(userAgent))
                .createdAt(now)
                .lastUsedAt(now)
                .expiresAt(now.plusMillis(jwtConfig.getRefreshExpiration()))
                .build());

        String raw = newRawToken();
        refreshTokenRepository.save(RefreshToken.builder()
                .sessionId(session.getId())
                .tokenHash(sha256(raw))
                .createdAt(now)
                .expiresAt(session.getExpiresAt())
                .build());

        return new IssuedRefresh(session, raw);
    }

    /**
     * Rotates the presented token. A rotated token re-presented within the
     * grace window returns the already-issued successor (network retry);
     * outside the grace it is replay — the whole session dies.
     * The reuse exception must NOT roll back the session revocation.
     */
    @Transactional(noRollbackFor = TokenReuseException.class)
    public RotationResult rotate(String rawToken) {
        String hash = sha256(rawToken);
        RefreshToken token = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        Session session = sessionRepository.findById(token.getSessionId())
                .orElseThrow(() -> new InvalidTokenException("Session not found"));

        if (!session.isAlive() || token.getRevokedAt() != null
                || token.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("Session expired or revoked");
        }

        if (token.getReplacedBy() != null) {
            return handleReplayedToken(token, session, hash);
        }

        Instant now = Instant.now();
        String newRaw = newRawToken();
        RefreshToken successor = refreshTokenRepository.save(RefreshToken.builder()
                .sessionId(session.getId())
                .tokenHash(sha256(newRaw))
                .createdAt(now)
                .expiresAt(session.getExpiresAt())
                .build());

        // Atomic head swap — a concurrent refresh of the same token loses here
        int updated = refreshTokenRepository.markReplaced(token.getId(), successor.getId(), now);
        if (updated == 0) {
            refreshTokenRepository.delete(successor);
            return handleReplayedToken(token, session, hash);
        }

        session.setLastUsedAt(now);
        sessionRepository.save(session);

        // Idempotent-retry cache: encrypted successor, single grace window
        redisTemplate.opsForValue().set(RETRY_PREFIX + hash,
                encryptionUtil.encrypt(newRaw), rotationGrace);

        return new RotationResult(session, newRaw, false);
    }

    @Transactional
    public void revokeSession(UUID sessionId, String reason) {
        sessionRepository.findById(sessionId).ifPresent(session -> {
            if (session.getRevokedAt() == null) {
                session.setRevokedAt(Instant.now());
                session.setRevokeReason(reason);
                sessionRepository.save(session);
                blacklistService.blacklistSid(session.getId(), jwtConfig.getExpiration());
            }
        });
    }

    @Transactional
    public void revokeAll(UUID identityId, String reason) {
        sessionRepository.findActiveByIdentity(identityId, Instant.now())
                .forEach(session -> revokeSession(session.getId(), reason));
    }

    @Transactional(readOnly = true)
    public List<Session> listActiveSessions(UUID identityId) {
        return sessionRepository.findActiveByIdentity(identityId, Instant.now());
    }

    private RotationResult handleReplayedToken(RefreshToken token, Session session, String hash) {
        boolean withinGrace = token.getReplacedAt() != null
                && token.getReplacedAt().plus(rotationGrace).isAfter(Instant.now());

        if (withinGrace) {
            String cached = redisTemplate.opsForValue().get(RETRY_PREFIX + hash);
            if (cached != null) {
                log.debug("Refresh retry within grace for session {}", session.getId());
                return new RotationResult(session, encryptionUtil.decrypt(cached), true);
            }
            throw new InvalidTokenException("Invalid refresh token");
        }

        // Replay outside grace: theft indicator — kill the whole session
        revokeSession(session.getId(), "REUSE_DETECTED");
        log.warn("Refresh token reuse detected — session {} revoked (identity {})",
                session.getId(), session.getIdentityId());
        throw new TokenReuseException("Refresh token reuse detected; session revoked");
    }

    // List is ordered most-recently-used first; evict from the tail until
    // the new session fits under the cap.
    private void evictBeyondCap(UUID identityId) {
        List<Session> active = sessionRepository.findActiveByIdentity(identityId, Instant.now());
        for (int i = active.size() - 1; i >= maxSessionsPerIdentity - 1 && i >= 0; i--) {
            revokeSession(active.get(i).getId(), "EVICTED");
            log.info("Evicted LRU session {} for identity {}", active.get(i).getId(), identityId);
        }
    }

    private String newRawToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String deviceLabel(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }
        return userAgent.length() <= 100 ? userAgent : userAgent.substring(0, 100);
    }
}
