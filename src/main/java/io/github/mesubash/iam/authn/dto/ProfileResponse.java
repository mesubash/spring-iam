package io.github.mesubash.iam.authn.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProfileResponse {
    private UUID id;
    private String email;
    private Boolean emailVerified;
    private String displayName;
    private String phone;
    private String country;
    private String avatarUrl;
    private OffsetDateTime lastLoginAt;
    private OffsetDateTime createdAt;
}
