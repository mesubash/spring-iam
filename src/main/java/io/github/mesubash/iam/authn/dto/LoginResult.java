package io.github.mesubash.iam.authn.dto;

/**
 * Outcome of a first factor (password or OAuth). Tokens are issued only on OK; otherwise the
 * caller gets a single-purpose token for the next step.
 */
public record LoginResult(Status status, JwtResponse tokens, String mfaToken) {

    public enum Status { OK, MFA_REQUIRED, MFA_ENROLLMENT_REQUIRED }

    public static LoginResult ok(JwtResponse tokens) {
        return new LoginResult(Status.OK, tokens, null);
    }

    public static LoginResult mfaRequired(String challenge) {
        return new LoginResult(Status.MFA_REQUIRED, null, challenge);
    }

    public static LoginResult enrollmentRequired(String enrollmentToken) {
        return new LoginResult(Status.MFA_ENROLLMENT_REQUIRED, null, enrollmentToken);
    }
}
