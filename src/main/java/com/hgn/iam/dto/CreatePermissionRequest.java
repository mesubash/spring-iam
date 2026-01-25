package com.hgn.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class CreatePermissionRequest {
    @NotBlank
    @Pattern(regexp = "^[a-z_]+\\.[a-z_]+\\.[a-z_]+$")
    private String key;

    @NotBlank
    private String domain;

    @NotBlank
    private String resource;

    @NotBlank
    private String action;

    private String description;
}
