package io.github.mesubash.iam.authn.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "app.jwt")
public class JwtConfig {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtConfig.class);

    private String secret;
    private String issuer = "spring-iam";
    private String audience;

    /**
     * Audiences a client may ask for (login / OAuth start / SSO authorize). Empty = feature off:
     * tokens carry {@link #audience} (or no aud) exactly as before.
     */
    private java.util.List<String> allowedAudiences = new java.util.ArrayList<>();

    /** What a session gets when the client names no audience: the single audience, else the first allowed. */
    public String defaultAudience() {
        if (audience != null && !audience.isBlank()) {
            return audience;
        }
        return allowedAudiences.isEmpty() ? null : allowedAudiences.get(0);
    }

    /** Every audience this IAM mints and therefore accepts: the allowed list plus the single audience. */
    public java.util.Set<String> acceptedAudiences() {
        java.util.Set<String> all = new java.util.LinkedHashSet<>(allowedAudiences);
        if (audience != null && !audience.isBlank()) {
            all.add(audience);
        }
        return all;
    }

    /**
     * Never returns a guessable default. When APP_JWT_SECRET is unset a random boot-time secret is
     * generated, so OAuth state cookies stay unforgeable (but only within this instance's lifetime).
     */
    public String getSecret() {
        if (secret == null || secret.isBlank()) {
            synchronized (this) {
                if (secret == null || secret.isBlank()) {
                    byte[] b = new byte[64];
                    new java.security.SecureRandom().nextBytes(b);
                    secret = java.util.Base64.getEncoder().encodeToString(b);
                    log.warn("APP_JWT_SECRET is unset: generated an ephemeral secret for this instance "
                            + "(OAuth state cookies won't survive restarts or span instances).");
                }
            }
        }
        return secret;
    }
    private long expiration;
    private long refreshExpiration;

    // How much authorization data rides in the access token:
    // minimal | roles (default) | permissions
    private String claimsMode = "roles";
}
