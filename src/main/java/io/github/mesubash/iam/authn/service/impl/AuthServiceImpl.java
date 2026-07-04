package io.github.mesubash.iam.authn.service.impl;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.PasswordChangeRequest;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.token.TokenService;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.authn.service.RefreshTokenBlacklistService;
import io.github.mesubash.iam.authn.service.SecurityEventService;
import io.github.mesubash.iam.shared.dto.RoleClaimsDto;
import io.github.mesubash.iam.shared.exception.*;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import io.github.mesubash.iam.shared.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenService tokenService;
    private final RefreshTokenBlacklistService refreshTokenBlacklistService;
    private final JwtConfig jwtConfig;
    private final AuthzQueryService authzQueryService;
    private final SecurityEventService securityEventService;

    @Value("${iam.account.lockout.max-attempts:5}")
    private int maxLoginAttempts;

    @Value("${iam.account.lockout.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        log.info("Registering new user with email: {}", request.getEmail());

        if (identityRepository.existsByPrimaryEmail(request.getEmail())) {
            throw new ConflictException("Email address already in use");
        }

        // Create identity
        Identity identity = Identity.builder()
                .primaryEmail(request.getEmail())
                .emailVerified(false)
                .accountStatus(AccountStatus.ACTIVE)
                .build();
        identity = identityRepository.save(identity);

        // Create password credential
        Credential credential = Credential.builder()
                .identity(identity)
                .credentialType(CredentialType.PASSWORD)
                .identifier(request.getEmail())
                .secretHash(passwordEncoder.encode(request.getPassword()))
                .build();
        credentialRepository.save(credential);

        // Generate verification token
        String verificationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), verificationToken, TokenType.EMAIL_VERIFICATION);

        // TODO: Send verification email via event/notification service
        log.info("User registered successfully: {}. Verification token generated.", request.getEmail());
    }

    @Override
    @Transactional
    public JwtResponse login(LoginRequest request) {
        log.info("User attempting to login: {}", request.getEmail());

        // Check if account is locked before attempting auth
        identityRepository.findByPrimaryEmail(request.getEmail()).ifPresent(this::checkAndUnlockIfExpired);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (BadCredentialsException ex) {
            handleFailedLogin(request.getEmail());
            throw new UnauthorizedException("Invalid email or password");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Identity identity = userPrincipal.getIdentity();

        if (!Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new UnauthorizedException("Email address is not verified. Please verify before logging in.");
        }

        ensureAccountActive(identity);

        // Update last login and reset failed attempts
        identity.setLastLoginAt(OffsetDateTime.now());
        identity.setFailedLoginAttempts(0);
        identity.setAccountLockedUntil(null);
        identityRepository.save(identity);

        String accessToken = jwtTokenProvider.generateToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication, false);
        long expiresIn = jwtConfig.getExpiration() / 1000;

        String userId = identity.getId().toString();
        tokenService.revokeAll(userId, TokenType.REFRESH);
        tokenService.store(userId, refreshToken, TokenType.REFRESH);

        securityEventService.logEvent(identity, SecurityEventType.LOGIN_SUCCESS, null, null);
        log.info("User logged in successfully: {}", request.getEmail());

        return new JwtResponse(accessToken, refreshToken, expiresIn, toIdentityInfo(identity));
    }

    @Override
    public JwtResponse refreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token is required");
        }

        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        if (refreshTokenBlacklistService.isBlacklisted(refreshToken)) {
            throw new TokenReuseException("Refresh token has been revoked");
        }

        String userId = jwtTokenProvider.getUserIdFromToken(refreshToken);

        if (!tokenService.validate(userId, refreshToken, TokenType.REFRESH)) {
            throw new TokenReuseException("Invalid refresh token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UnauthorizedException("Invalid or expired refresh token"));

        ensureAccountActive(identity);

        // Get fresh roles from AuthZ
        List<String> roles = getRolesForIdentity(identity.getId());

        UserPrincipal userPrincipal = UserPrincipal.create(identity, null, roles);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userPrincipal, null, userPrincipal.getAuthorities());

        String newAccessToken = jwtTokenProvider.generateToken(authentication);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(authentication, false);
        long expiresIn = jwtConfig.getExpiration() / 1000;

        tokenService.rotate(userId, refreshToken, newRefreshToken, TokenType.REFRESH);

        return new JwtResponse(newAccessToken, newRefreshToken, expiresIn, toIdentityInfo(identity));
    }

    @Override
    @Transactional
    public JwtResponse validateAndRefreshToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new InvalidTokenException("Access token is required");
        }

        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new InvalidTokenException("Invalid access token");
        }

        String userId = jwtTokenProvider.getUserIdFromToken(accessToken);
        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        ensureAccountActive(identity);

        List<String> roles = getRolesForIdentity(identity.getId());

        UserPrincipal userPrincipal = UserPrincipal.create(identity, null, roles);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userPrincipal, null, userPrincipal.getAuthorities());

        String newAccessToken = jwtTokenProvider.generateToken(authentication);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(authentication, false);
        long expiresIn = jwtConfig.getExpiration() / 1000;

        tokenService.revokeAll(userId, TokenType.REFRESH);
        tokenService.store(userId, newRefreshToken, TokenType.REFRESH);

        return new JwtResponse(newAccessToken, newRefreshToken, expiresIn, toIdentityInfo(identity));
    }

    @Override
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        String userId = null;

        if (accessToken != null && !accessToken.isBlank()) {
            try {
                userId = jwtTokenProvider.getUserIdFromToken(accessToken);
                long remainingTime = jwtTokenProvider.getExpirationTime(accessToken);
                if (remainingTime > 0) {
                    tokenService.blacklistToken(accessToken, remainingTime);
                }
            } catch (Exception ex) {
                log.warn("Failed to process access token during logout: {}", ex.getMessage());
            }
        }

        if (refreshToken != null && !refreshToken.isBlank()) {
            try {
                String refreshTokenUserId = jwtTokenProvider.getUserIdFromToken(refreshToken);
                tokenService.revoke(refreshTokenUserId, refreshToken, TokenType.REFRESH);

                Date expirationDate = jwtTokenProvider.getExpirationDateFromToken(refreshToken);
                OffsetDateTime expiresAt = OffsetDateTime.ofInstant(
                        expirationDate.toInstant(), ZoneOffset.UTC);
                refreshTokenBlacklistService.blacklistToken(
                        refreshToken, UUID.fromString(refreshTokenUserId), expiresAt, "LOGOUT");
            } catch (Exception ex) {
                log.warn("Failed to revoke refresh token during logout: {}", ex.getMessage());
                if (userId != null) {
                    tokenService.revokeAll(userId, TokenType.REFRESH);
                }
            }
        } else if (userId != null) {
            tokenService.revokeAll(userId, TokenType.REFRESH);
        }
    }

    @Override
    public void forgotPassword(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String resetToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), resetToken, TokenType.PASSWORD_RESET);

        // TODO: Send password reset email via notification service
        log.info("Password reset token generated for: {}", email);
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        String userId = tokenService.getTokenUserId(token, TokenType.PASSWORD_RESET);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new ResourceNotFoundException("Password credential not found"));

        credential.setSecretHash(passwordEncoder.encode(newPassword));
        credentialRepository.save(credential);

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_RESET, null, null);
        tokenService.revoke(userId, token, TokenType.PASSWORD_RESET);
    }

    @Override
    @Transactional
    public void changePassword(String email, PasswordChangeRequest request) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new ResourceNotFoundException("Password credential not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), credential.getSecretHash())) {
            throw new BadRequestException("Current password is incorrect");
        }

        credential.setSecretHash(passwordEncoder.encode(request.getNewPassword()));
        credentialRepository.save(credential);

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_CHANGED, null, null);
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        String userId = tokenService.getTokenUserId(token, TokenType.EMAIL_VERIFICATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        identity.setEmailVerified(true);
        identityRepository.save(identity);

        tokenService.revoke(userId, token, TokenType.EMAIL_VERIFICATION);
    }

    @Override
    @Transactional
    public void verifyEmailAndSetupPassword(String token, String newPassword) {
        String userId = tokenService.getTokenUserId(token, TokenType.EMAIL_VERIFICATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        identity.setEmailVerified(true);
        identityRepository.save(identity);

        // Create or update password credential
        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseGet(() -> Credential.builder()
                        .identity(identity)
                        .credentialType(CredentialType.PASSWORD)
                        .identifier(identity.getPrimaryEmail())
                        .build());

        credential.setSecretHash(passwordEncoder.encode(newPassword));
        credentialRepository.save(credential);

        tokenService.revoke(userId, token, TokenType.EMAIL_VERIFICATION);
    }

    @Override
    public void resendVerification(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new BadRequestException("Email already verified");
        }

        String verificationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), verificationToken, TokenType.EMAIL_VERIFICATION);

        // TODO: Send verification email via notification service
        log.info("Verification token regenerated for: {}", email);
    }

    @Override
    @Transactional
    public void logoutAll(String userId) {
        tokenService.revokeAll(userId, TokenType.REFRESH);

        identityRepository.findById(UUID.fromString(userId))
                .ifPresent(identity -> securityEventService.logEvent(
                        identity, SecurityEventType.TOKEN_REVOKED, null, null,
                        Map.of("action", "logout_all")));

        log.info("Revoked all sessions for user: {}", userId);
    }

    @Override
    public void requestReactivation(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (identity.getAccountStatus() != AccountStatus.DEACTIVATED) {
            throw new BadRequestException("Account is not deactivated");
        }

        String reactivationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), reactivationToken, TokenType.ACCOUNT_REACTIVATION);

        // TODO: Send reactivation email via notification service
        log.info("Reactivation token generated for: {}", email);
    }

    @Override
    @Transactional
    public void verifyReactivation(String token) {
        String userId = tokenService.getTokenUserId(token, TokenType.ACCOUNT_REACTIVATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired reactivation token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (identity.getAccountStatus() != AccountStatus.DEACTIVATED) {
            throw new BadRequestException("Account is not deactivated");
        }

        identity.setAccountStatus(AccountStatus.ACTIVE);
        identity.setFailedLoginAttempts(0);
        identity.setAccountLockedUntil(null);
        identityRepository.save(identity);

        tokenService.revoke(userId, token, TokenType.ACCOUNT_REACTIVATION);
        log.info("Account reactivated for user: {}", userId);
    }

    private void handleFailedLogin(String email) {
        identityRepository.findByPrimaryEmail(email).ifPresent(identity -> {
            int attempts = (identity.getFailedLoginAttempts() != null ? identity.getFailedLoginAttempts() : 0) + 1;
            identity.setFailedLoginAttempts(attempts);

            if (attempts >= maxLoginAttempts) {
                identity.setAccountStatus(AccountStatus.LOCKED);
                identity.setAccountLockedUntil(OffsetDateTime.now().plusMinutes(lockoutDurationMinutes));
                securityEventService.logEvent(identity, SecurityEventType.ACCOUNT_LOCKED, null, null,
                        Map.of("reason", "max_login_attempts_exceeded", "attempts", attempts));
                log.warn("Account locked for {} after {} failed attempts", email, attempts);
            } else {
                securityEventService.logEvent(identity, SecurityEventType.LOGIN_FAILED, null, null,
                        Map.of("attempts", attempts));
            }

            identityRepository.save(identity);
        });
    }

    private void checkAndUnlockIfExpired(Identity identity) {
        if (identity.getAccountStatus() == AccountStatus.LOCKED
                && identity.getAccountLockedUntil() != null
                && OffsetDateTime.now().isAfter(identity.getAccountLockedUntil())) {
            identity.setAccountStatus(AccountStatus.ACTIVE);
            identity.setFailedLoginAttempts(0);
            identity.setAccountLockedUntil(null);
            identityRepository.save(identity);
            securityEventService.logEvent(identity, SecurityEventType.ACCOUNT_UNLOCKED, null, null,
                    Map.of("reason", "lockout_expired"));
            log.info("Account auto-unlocked for: {}", identity.getPrimaryEmail());
        }
    }

    private void ensureAccountActive(Identity identity) {
        AccountStatus status = identity.getAccountStatus();
        if (status != AccountStatus.ACTIVE) {
            String message = switch (status) {
                case LOCKED -> "Account is locked. Please try again later or contact support.";
                case SUSPENDED -> "Account is suspended. Please contact support.";
                case DEACTIVATED -> "Account is deactivated. Please reactivate your account.";
                default -> "Account is not active. Please contact support.";
            };
            throw new UnauthorizedException(message);
        }
    }

    private List<String> getRolesForIdentity(UUID identityId) {
        try {
            RoleClaimsDto roleClaims = authzQueryService.getRolesForIdentity(identityId);
            return roleClaims != null && roleClaims.getRoles() != null ? roleClaims.getRoles() : List.of();
        } catch (Exception e) {
            return List.of();
        }
    }

    private JwtResponse.IdentityInfo toIdentityInfo(Identity identity) {
        JwtResponse.IdentityInfo info = JwtResponse.IdentityInfo.builder()
                .id(identity.getId())
                .email(identity.getPrimaryEmail())
                .emailVerified(identity.getEmailVerified())
                .build();

        return info;
    }
}
