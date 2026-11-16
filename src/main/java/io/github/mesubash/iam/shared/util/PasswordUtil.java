package io.github.mesubash.iam.shared.util;

import java.security.SecureRandom;
import java.util.Base64;

public final class PasswordUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PasswordUtil() {}

    public static String generateSecureToken(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static final int MIN_PASSWORD_LENGTH = 6;
    // BCrypt only hashes the first 72 bytes; longer input is wasted work and a CPU-DoS vector.
    public static final int MAX_PASSWORD_LENGTH = 72;

    /**
     * Server-side password policy: {@value #MIN_PASSWORD_LENGTH}-{@value #MAX_PASSWORD_LENGTH}
     * chars with a letter and a digit. Returns null when valid, else the reason. Enforced on
     * every path a user sets their own password, whatever the request DTO allows.
     */
    public static String policyViolation(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            return "Password must be at least " + MIN_PASSWORD_LENGTH + " characters";
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            return "Password must be at most " + MAX_PASSWORD_LENGTH + " characters";
        }
        if (password.chars().noneMatch(Character::isLetter) || password.chars().noneMatch(Character::isDigit)) {
            return "Password must contain at least one letter and one digit";
        }
        return null;
    }
}
