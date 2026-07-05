package io.github.mesubash.iam.authn.dto;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Admin password reset for another account. If newPassword is omitted the
 * server generates a temporary one and returns it exactly once.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminSetPasswordRequest {

    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String newPassword;

    /** Revoke the user's sessions so the new password takes effect everywhere. */
    private Boolean revokeSessions;
}
