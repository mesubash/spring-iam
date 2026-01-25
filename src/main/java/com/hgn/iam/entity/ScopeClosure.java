package com.hgn.iam.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "scope_closure")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@IdClass(ScopeClosureId.class)
public class ScopeClosure {

    @Id
    @Column(name = "ancestor_id")
    private UUID ancestorId;

    @Id
    @Column(name = "descendant_id")
    private UUID descendantId;

    @Column(nullable = false)
    private Integer depth;
}

