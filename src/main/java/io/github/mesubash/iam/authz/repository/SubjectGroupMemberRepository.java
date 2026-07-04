package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.SubjectGroupMember;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SubjectGroupMemberRepository
        extends JpaRepository<SubjectGroupMember, SubjectGroupMember.Key> {

    @Query("SELECT m.groupId FROM SubjectGroupMember m JOIN SubjectGroup g ON g.id = m.groupId " +
           "WHERE m.subjectId = :subjectId AND g.active = true")
    List<UUID> findActiveGroupIds(@Param("subjectId") String subjectId);

    List<SubjectGroupMember> findByGroupId(UUID groupId);
}
