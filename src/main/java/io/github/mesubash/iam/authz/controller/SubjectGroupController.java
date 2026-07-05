package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.SubjectGroup;
import io.github.mesubash.iam.authz.entity.SubjectGroupMember;
import io.github.mesubash.iam.authz.repository.SubjectGroupMemberRepository;
import io.github.mesubash.iam.authz.repository.SubjectGroupRepository;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/groups")
@RequiredArgsConstructor
@Tag(name = "Groups", description = "Subject groups: one assignment or deny rule covers every member")
public class SubjectGroupController {

    private final SubjectGroupRepository groupRepository;
    private final SubjectGroupMemberRepository memberRepository;
    private final FeatureFlags featureFlags;

    @GetMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<List<SubjectGroup>> list() {
        requireEnabled();
        return ResponseEntity.ok(groupRepository.findAll());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<SubjectGroup> create(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody CreateGroupRequest request) {
        requireEnabled();
        SubjectGroup group = groupRepository.save(SubjectGroup.builder()
                .name(request.getName())
                .description(request.getDescription())
                .createdAt(Instant.now())
                .createdBy(caller.getId().toString())
                .build());
        return ResponseEntity.status(HttpStatus.CREATED).body(group);
    }

    @GetMapping("/{id}/members")
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<List<SubjectGroupMember>> members(@PathVariable UUID id) {
        requireEnabled();
        return ResponseEntity.ok(memberRepository.findByGroupId(id));
    }

    @PostMapping("/{id}/members")
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<Void> addMember(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id,
            @Valid @RequestBody MemberRequest request) {
        requireEnabled();
        groupRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Group not found"));
        memberRepository.save(SubjectGroupMember.builder()
                .groupId(id)
                .subjectId(request.getSubjectId())
                .addedAt(Instant.now())
                .addedBy(caller.getId().toString())
                .build());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @DeleteMapping("/{id}/members/{subjectId}")
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<Void> removeMember(@PathVariable UUID id, @PathVariable String subjectId) {
        requireEnabled();
        memberRepository.deleteById(new SubjectGroupMember.Key(id, subjectId));
        return ResponseEntity.noContent().build();
    }

    private void requireEnabled() {
        if (!featureFlags.isGroups()) {
            throw new ResourceNotFoundException("Groups are not enabled");
        }
    }

    @Data
    public static class CreateGroupRequest {
        @NotBlank
        private String name;
        private String description;
    }

    @Data
    public static class MemberRequest {
        @NotBlank
        private String subjectId;
    }
}
