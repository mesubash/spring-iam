package io.github.mesubash.iam.authn.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminUpdateStatusRequest {

    /** LOCKED is managed by the lockout machinery, not set by hand. */
    @NotNull(message = "Status is required")
    @Pattern(regexp = "ACTIVE|SUSPENDED|DEACTIVATED",
            message = "Status must be ACTIVE, SUSPENDED or DEACTIVATED")
    private String status;

    private String reason;
}
