package com.hgn.iam.authn.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for user registration request - minimal fields for fast signup
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User registration request with minimal required fields")
public class RegisterRequest {

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    @Schema(description = "Full name of the user", example = "John Doe", required = true, minLength = 2, maxLength = 100)
    private String fullName;

    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    @Schema(description = "Email address (must be unique)", example = "john.doe@example.com", required = true, format = "email")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    @Schema(description = "Password (minimum 6 characters)", example = "SecurePass123", required = true, minLength = 6, format = "password")
    private String password;

}

