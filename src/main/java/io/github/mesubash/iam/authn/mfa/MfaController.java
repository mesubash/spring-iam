package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.exception.UnauthorizedException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * TOTP enrollment and lifecycle. setup/enable accept EITHER a signed-in caller OR the
 * enrollment token a login returned (forced enrollment for roles in iam.mfa.required-roles).
 * The second login step, POST /api/auth/mfa/verify, lives in AuthController next to the
 * refresh-cookie handling.
 */
@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
@Tag(name = "MFA", description = "Multi-factor authentication (TOTP + recovery codes)")
public class MfaController {

    private final MfaService mfaService;
    private final MfaChallengeService challengeService;
    private final IdentityRepository identityRepository;

    @PostMapping("/setup")
    @Operation(summary = "Begin MFA enrollment: returns a secret and otpauth:// URI")
    public ResponseEntity<ApiResponse<MfaService.SetupResult>> setup(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestBody(required = false) MfaRequests.Setup body) {
        UUID id = resolveEnrollee(principal, body == null ? null : body.enrollmentToken());
        String email = identityRepository.findById(id).map(i -> i.getPrimaryEmail()).orElse("");
        return ResponseEntity.ok(ApiResponse.success("MFA setup started", mfaService.setup(id, email)));
    }

    @PostMapping("/enable")
    @Operation(summary = "Confirm a code and enable MFA; returns recovery codes once")
    public ResponseEntity<ApiResponse<Map<String, List<String>>>> enable(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody MfaRequests.Enable body) {
        UUID id = resolveEnrollee(principal, body.enrollmentToken());
        List<String> recovery = mfaService.enable(id, body.code());
        challengeService.clearEnrollment(body.enrollmentToken());
        return ResponseEntity.ok(ApiResponse.success("MFA enabled", Map.of("recoveryCodes", recovery)));
    }

    @PostMapping("/disable")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Disable MFA (requires a current TOTP or recovery code)")
    public ResponseEntity<ApiResponse<Void>> disable(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody MfaRequests.Code body) {
        mfaService.disable(principal.getId(), body.code());
        return ResponseEntity.ok(ApiResponse.success("MFA disabled", null));
    }

    @PostMapping("/recovery-codes")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Regenerate recovery codes (requires a current TOTP code)")
    public ResponseEntity<ApiResponse<Map<String, List<String>>>> recoveryCodes(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody MfaRequests.Code body) {
        List<String> codes = mfaService.regenerateRecoveryCodes(principal.getId(), body.code());
        return ResponseEntity.ok(ApiResponse.success("Recovery codes regenerated", Map.of("recoveryCodes", codes)));
    }

    /** setup/enable: the signed-in caller, else a valid enrollment token. */
    private UUID resolveEnrollee(UserPrincipal principal, String enrollmentToken) {
        if (principal != null) {
            return principal.getId();
        }
        return challengeService.peekEnrollment(enrollmentToken)
                .orElseThrow(() -> new UnauthorizedException(
                        "Authentication or a valid enrollment token is required"));
    }
}
