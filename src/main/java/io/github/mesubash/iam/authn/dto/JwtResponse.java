package io.github.mesubash.iam.authn.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JwtResponse {
    private String accessToken;
    @Builder.Default
    private String tokenType = "Bearer";
    private long expiresIn;
    private IdentityInfo identity;

    @JsonIgnore
    private String refreshToken;

    public JwtResponse(String accessToken, String refreshToken, long expiresIn, IdentityInfo identity) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.identity = identity;
    }

    public JwtResponse(String accessToken, long expiresIn, IdentityInfo identity) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.expiresIn = expiresIn;
        this.identity = identity;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IdentityInfo {
        private UUID id;
        private String email;
        private String displayName;
        private Boolean emailVerified;
    }
}
