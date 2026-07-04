package io.github.mesubash.iam.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EffectivePermissionsResponse {

    private String subject;
    private UUID scopeId;
    private Set<String> permissions;
    private Set<String> deniedPermissions;
}
