package io.github.mesubash.iam.shared.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdentitySummaryDto {
    private UUID id;
    private String email;
    private String accountStatus;
}
