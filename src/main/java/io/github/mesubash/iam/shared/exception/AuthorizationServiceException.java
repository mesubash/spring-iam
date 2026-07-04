package io.github.mesubash.iam.shared.exception;

/**
 * Thrown when the authorization service encounters an infrastructure error
 * (e.g., database or Redis unavailable). This should result in a 503 response,
 * NOT a security denial — failing open to "deny" on infra errors is the wrong
 * default for a centralized IAM service, as it blocks all users.
 */
public class AuthorizationServiceException extends RuntimeException {
    public AuthorizationServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
