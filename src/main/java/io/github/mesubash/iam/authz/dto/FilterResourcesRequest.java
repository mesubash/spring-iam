package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Filter a list of resource ids down to those the subject may act on. */
@Data
public class FilterResourcesRequest {

    @NotBlank
    private String subjectId;

    @NotBlank
    private String permission;

    @NotBlank
    private String resourceType;

    @NotNull
    private List<String> resourceIds;

    private UUID scopeId;

    private Map<String, Object> context;
}
