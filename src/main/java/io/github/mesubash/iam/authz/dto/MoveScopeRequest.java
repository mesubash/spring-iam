package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class MoveScopeRequest {

    @NotNull
    private UUID newParentId;
}
