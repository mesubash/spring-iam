package io.github.mesubash.iam.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/** Full decision trace for the "why?" debugger. No audit record is written. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExplainResponse {

    private boolean allowed;
    private String reason;
    private List<Step> steps;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Step {
        private String name;      // deny_rules | rbac_scope | conditions | resource_grants | policies
        private String outcome;   // PASS | FAIL | SKIP | ALLOW | DENY
        private String detail;    // human-readable explanation of what fired
    }
}
