package io.github.mesubash.iam.authn.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Admin-initiated user creation. If password is omitted the server generates
 * a temporary one and returns it exactly once in the response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminCreateIdentityRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    private String email;

    @Size(min = 6, message = "Password must be at least 6 characters long")
    private String password;

    /** Admin-created accounts default to verified (no self-serve email loop). */
    private Boolean emailVerified;
}
