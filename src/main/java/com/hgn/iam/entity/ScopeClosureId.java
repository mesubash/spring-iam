package com.hgn.iam.entity;

import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
class ScopeClosureId implements java.io.Serializable {
    private UUID ancestorId;
    private UUID descendantId;
}
