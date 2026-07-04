package io.github.mesubash.iam.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EffectivePermissionsRequest {

    private String subject;
    private UUID scopeId;
    private AuthorizationRequest.ResourceContext resource;
    private AuthorizationRequest.RequestContext context;
    // Boxed: a primitive here made Jackson reject any body omitting the field
    private Boolean includeDenied;

    public boolean isIncludeDenied() {
        return Boolean.TRUE.equals(includeDenied);
    }
}
