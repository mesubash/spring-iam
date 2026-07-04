package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.dto.ProfileResponse;
import io.github.mesubash.iam.authn.dto.UpdateProfileRequest;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.entity.IdentityProfile;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.github.mesubash.iam.shared.repository.IdentityProfileRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth/me")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
@Tag(name = "Profile", description = "User profile management")
public class ProfileController {

    private final IdentityRepository identityRepository;
    private final IdentityProfileRepository identityProfileRepository;

    @GetMapping
    @Operation(summary = "Get my profile", description = "Returns the current user's identity and profile information")
    public ResponseEntity<ApiResponse<ProfileResponse>> getProfile(
            @AuthenticationPrincipal UserPrincipal principal) {
        UUID identityId = principal.getId();

        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new ResourceNotFoundException("Identity not found"));

        ProfileResponse.ProfileResponseBuilder builder = ProfileResponse.builder()
                .id(identity.getId())
                .email(identity.getPrimaryEmail())
                .emailVerified(identity.getEmailVerified())
                .lastLoginAt(identity.getLastLoginAt())
                .createdAt(identity.getCreatedAt());

        identityProfileRepository.findById(identityId)
                .ifPresent(profile -> {
                    builder.displayName(profile.getDisplayName());
                    builder.phone(profile.getPhone());
                    builder.country(profile.getCountry());
                    builder.avatarUrl(profile.getAvatarUrl());
                });

        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", builder.build()));
    }

    @PutMapping
    @Operation(summary = "Update my profile", description = "Update the current user's profile information")
    public ResponseEntity<ApiResponse<ProfileResponse>> updateProfile(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody UpdateProfileRequest request) {
        UUID identityId = principal.getId();

        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new ResourceNotFoundException("Identity not found"));

        IdentityProfile profile = identityProfileRepository.findById(identityId)
                .orElse(IdentityProfile.builder()
                        .identityId(identityId)
                        .displayName(identity.getPrimaryEmail())
                        .email(identity.getPrimaryEmail())
                        .build());

        if (StringUtils.hasText(request.getDisplayName())) {
            profile.setDisplayName(request.getDisplayName());
        }
        if (request.getPhone() != null) {
            profile.setPhone(request.getPhone());
        }
        if (request.getCountry() != null) {
            profile.setCountry(request.getCountry());
        }
        if (request.getAvatarUrl() != null) {
            profile.setAvatarUrl(request.getAvatarUrl());
        }

        identityProfileRepository.save(profile);

        ProfileResponse response = ProfileResponse.builder()
                .id(identity.getId())
                .email(identity.getPrimaryEmail())
                .emailVerified(identity.getEmailVerified())
                .displayName(profile.getDisplayName())
                .phone(profile.getPhone())
                .country(profile.getCountry())
                .avatarUrl(profile.getAvatarUrl())
                .lastLoginAt(identity.getLastLoginAt())
                .createdAt(identity.getCreatedAt())
                .build();

        return ResponseEntity.ok(ApiResponse.success("Profile updated", response));
    }
}
