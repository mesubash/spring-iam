package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class CreatePermissionRequest {
    // domain.<resource-path>.action — 3 to 6 dot-separated segments, digits allowed
    @NotBlank
    @Pattern(regexp = "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){2,5}$")
    private String key;

    @NotBlank
    private String domain;

    @NotBlank
    private String resource;

    @NotBlank
    private String action;

    private String description;
}
