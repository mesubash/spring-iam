package io.github.mesubash.iam.authn.mfa;

import jakarta.validation.constraints.NotBlank;

/** Typed request bodies for the MFA endpoints (replaces raw string maps). */
public final class MfaRequests {

    private MfaRequests() {
    }

    /** setup: authenticated caller OR a forced-enrollment token from login. */
    public record Setup(String enrollmentToken) {}

    /** enable: the first valid code confirms enrollment. */
    public record Enable(String enrollmentToken, @NotBlank String code) {}

    /** disable / recovery-codes: requires a current code. */
    public record Code(@NotBlank String code) {}

    /** verify: second login step against the challenge from /login or /oauth/exchange. */
    public record Verify(@NotBlank String challenge, @NotBlank String code) {}
}
