package io.github.mesubash.iam.authz.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.UUID;

/** What-if: evaluate an authorization request with a hypothetical assignment set. */
@Data
public class SimulateRequest {

    @NotNull
    @Valid
    private AuthorizationRequest request;

    private List<Hypothetical> addAssignments = List.of();
    private List<UUID> removeAssignmentIds = List.of();

    @Data
    public static class Hypothetical {
        private UUID roleId;
        private UUID scopeId;
    }
}
