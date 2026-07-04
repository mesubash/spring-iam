package io.github.mesubash.iam.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Who holds a permission at a scope. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessListEntry {
    private String subjectId;
    // true when the grant carries conditions/policies whose live verdict is context-dependent
    private boolean conditional;
}
