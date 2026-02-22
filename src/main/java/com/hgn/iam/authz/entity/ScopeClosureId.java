package com.hgn.iam.authz.entity;

import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class ScopeClosureId implements java.io.Serializable {
    private UUID ancestorId;
    private UUID descendantId;
}
