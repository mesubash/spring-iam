package com.hgn.iam.authn.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request payload for verifying an email address and immediately setting a password.
 */
@Data
public class VerifyEmailAndPasswordRequest {

    @NotBlank(message = "Verification token is required")
    private String token;

    @NotBlank(message = "New password is required")
    private String newPassword;
}
