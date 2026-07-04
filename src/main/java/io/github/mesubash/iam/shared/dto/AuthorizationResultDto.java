package io.github.mesubash.iam.shared.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationResultDto {
    private boolean authorized;
    private String reason;

    public static AuthorizationResultDto allowed() {
        return AuthorizationResultDto.builder()
                .authorized(true)
                .reason("ALLOWED")
                .build();
    }

    public static AuthorizationResultDto denied(String reason) {
        return AuthorizationResultDto.builder()
                .authorized(false)
                .reason(reason)
                .build();
    }
}
