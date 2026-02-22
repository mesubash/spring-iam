package com.hgn.iam.shared.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationRequestDto {
    private UUID subjectId;
    private String permissionKey;
    private UUID scopeId;
    private String resourceType;
    private String resourceId;
    private Map<String, Object> context;
}
