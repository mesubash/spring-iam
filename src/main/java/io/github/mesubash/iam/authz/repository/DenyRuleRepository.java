package io.github.mesubash.iam.authz.repository;
import io.github.mesubash.iam.authz.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface DenyRuleRepository extends JpaRepository<DenyRule, UUID> {

    @Query("SELECT dr FROM DenyRule dr " +
            "WHERE dr.subjectId = :subjectId " +
            "AND (dr.permissionKey = :permissionKey OR dr.permissionKey = '*.*.*') " +
            "AND dr.active = true " +
            "AND (dr.expiresAt IS NULL OR dr.expiresAt > :now)")
    List<DenyRule> findActiveDenyRules(@Param("subjectId") String subjectId,
                                       @Param("permissionKey") String permissionKey,
                                       @Param("now") Instant now);

    @Query("SELECT dr FROM DenyRule dr " +
            "WHERE dr.subjectId = :subjectId " +
            "AND dr.active = true " +
            "AND (dr.expiresAt IS NULL OR dr.expiresAt > :now)")
    List<DenyRule> findAllActiveDenyRulesForSubject(@Param("subjectId") String subjectId,
                                                    @Param("now") Instant now);
}
