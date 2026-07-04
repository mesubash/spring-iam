package io.github.mesubash.iam.shared.exception;


import io.github.mesubash.iam.shared.dto.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handle validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Failed")
                .message("Input validation failed")
                .validationErrors(errors)
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex, WebRequest request) {

        log.warn("Illegal argument: {}", ex.getMessage());

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle database constraint errors (friendly message)
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDataAccess(
            DataAccessException ex, WebRequest request) {

        String message = resolveDataAccessMessage(ex);

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Database Constraint Violation")
                .message(message)
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle generic exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, WebRequest request) {

        log.error("Unexpected error", ex);

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Internal Server Error")
                .message("An unexpected error occurred")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Handle 404 - no handler for URL
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoHandlerFound(
            NoHandlerFoundException ex, WebRequest request) {

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Not Found")
                .message("No handler found for " + ex.getHttpMethod() + " " + ex.getRequestURL())
                .path(ex.getRequestURL())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    /**
     * Handle 405 - method not allowed
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, WebRequest request) {

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.METHOD_NOT_ALLOWED.value())
                .error("Method Not Allowed")
                .message("Method " + ex.getMethod() + " is not supported for this endpoint.")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(response);
    }

    /**
     * Handle 415 - unsupported media type
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex, WebRequest request) {

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value())
                .error("Unsupported Media Type")
                .message("Content-Type is not supported. Please use application/json.")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(response);
    }

    /**
     * Handle malformed JSON / wrong payload type
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(
            HttpMessageNotReadableException ex, WebRequest request) {

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message("Invalid request body. Expected a JSON object or array matching the API contract.")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle unauthorized access — missing or invalid credentials (401)
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(
            UnauthorizedException ex, WebRequest request) {

        log.warn("Unauthorized: {}", ex.getMessage());

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(ConflictException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.CONFLICT.value())
                .error("Conflict")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Not Found")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(BadRequestException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler({InvalidTokenException.class, TokenExpiredException.class, TokenReuseException.class})
    public ResponseEntity<ErrorResponse> handleTokenException(RuntimeException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ErrorResponse> handleForbidden(ForbiddenException ex, WebRequest request) {
        log.warn("Forbidden: {}", ex.getMessage());
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ErrorResponse> handleEmailNotVerified(EmailNotVerifiedException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Email Not Verified")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(AuthorizationServiceException.class)
    public ResponseEntity<ErrorResponse> handleAuthorizationServiceError(
            AuthorizationServiceException ex, WebRequest request) {
        log.error("Authorization service unavailable: {}", ex.getMessage(), ex);
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                .error("Service Unavailable")
                .message("Authorization service is temporarily unavailable. Please retry.")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message("Invalid email or password")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // Bean-validation on request bodies whose element/param constraints throw
    // ConstraintViolationException (e.g. List<@Valid ...>) — surface as 400.
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
        java.util.Map<String, String> violations = new java.util.HashMap<>();
        ex.getConstraintViolations().forEach(v ->
                violations.put(v.getPropertyPath().toString(), v.getMessage()));
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Failed")
                .message("Request contains invalid values")
                .validationErrors(violations)
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.badRequest().body(response);
    }

    // Boot 4 wraps method-parameter/element validation (e.g. List<@Valid ...>)
    // in this instead of ConstraintViolationException.
    @ExceptionHandler(org.springframework.web.method.annotation.HandlerMethodValidationException.class)
    public ResponseEntity<ErrorResponse> handleHandlerMethodValidation(
            org.springframework.web.method.annotation.HandlerMethodValidationException ex, WebRequest request) {
        java.util.Map<String, String> violations = new java.util.HashMap<>();
        int[] i = {0};
        ex.getAllErrors().forEach(err -> {
            String field = err instanceof org.springframework.validation.FieldError fe
                    ? fe.getField() : "param" + i[0]++;
            violations.put(field, err.getDefaultMessage());
        });
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Failed")
                .message("Request contains invalid values")
                .validationErrors(violations)
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.badRequest().body(response);
    }

    // Login-time account states surfaced by the authentication provider.
    // (EmailNotVerifiedException has its own 403 handler above.)
    @ExceptionHandler({DisabledException.class, LockedException.class})
    public ResponseEntity<ErrorResponse> handleAccountState(RuntimeException ex, WebRequest request) {
        String message = ex instanceof LockedException
                ? "Account is locked. Please try again later or contact support."
                : "Account is not active or email is not verified.";
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message(message)
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // The provider wraps loadUser failures (e.g. email-not-verified) in this.
    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<ErrorResponse> handleInternalAuth(InternalAuthenticationServiceException ex, WebRequest request) {
        Throwable cause = ex.getCause();
        if (cause instanceof EmailNotVerifiedException enve) {
            return handleEmailNotVerified(enve, request);
        }
        if (cause instanceof UnauthorizedException) {
            return handleUnauthorized((UnauthorizedException) cause, request);
        }
        log.error("Authentication service error", ex);
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message("Authentication failed")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    private String resolveDataAccessMessage(Throwable ex) {
        String raw = rootCauseMessage(ex);
        if (raw == null) {
            return "Database operation failed.";
        }

        Pattern duplicatePattern = Pattern.compile(
                "duplicate key value violates unique constraint \"([^\"]+)\"");
        Matcher duplicateMatcher = duplicatePattern.matcher(raw);
        if (duplicateMatcher.find()) {
            Pattern detailPattern = Pattern.compile("Key \\(([^)]+)\\)=\\(([^)]+)\\) already exists");
            Matcher detailMatcher = detailPattern.matcher(raw);
            if (detailMatcher.find()) {
                return "Duplicate value for " + detailMatcher.group(1) + ": " + detailMatcher.group(2) + ".";
            }
            return "Duplicate value violates unique constraint: " + duplicateMatcher.group(1) + ".";
        }

        Pattern fkPattern = Pattern.compile(
                "violates foreign key constraint \"([^\"]+)\"");
        Matcher fkMatcher = fkPattern.matcher(raw);
        if (fkMatcher.find()) {
            Pattern fkDetail = Pattern.compile(
                    "Key \\(([^)]+)\\)=\\(([^)]+)\\) is not present in table \"([^\"]+)\"");
            Matcher fkDetailMatcher = fkDetail.matcher(raw);
            if (fkDetailMatcher.find()) {
                return "Invalid reference: " + fkDetailMatcher.group(1) + "=" + fkDetailMatcher.group(2)
                        + " does not exist in " + fkDetailMatcher.group(3) + ".";
            }
            return "Invalid reference (foreign key constraint): " + fkMatcher.group(1) + ".";
        }

        Pattern notNullPattern = Pattern.compile(
                "null value in column \"([^\"]+)\" violates not-null constraint");
        Matcher notNullMatcher = notNullPattern.matcher(raw);
        if (notNullMatcher.find()) {
            return "Missing required field: " + notNullMatcher.group(1) + ".";
        }

        Pattern checkPattern = Pattern.compile(
                "violates check constraint \"([^\"]+)\"");
        Matcher checkMatcher = checkPattern.matcher(raw);
        if (checkMatcher.find()) {
            String constraint = checkMatcher.group(1);
            String friendly = mapCheckConstraint(constraint);
            return friendly != null ? friendly : "Check constraint violated: " + constraint + ".";
        }

        Pattern uuidPattern = Pattern.compile("invalid input syntax for type uuid: \"([^\"]+)\"");
        Matcher uuidMatcher = uuidPattern.matcher(raw);
        if (uuidMatcher.find()) {
            return "Invalid UUID format: " + uuidMatcher.group(1) + ".";
        }

        if (raw.contains("invalid input syntax for type json")
                || raw.contains("invalid input syntax for type jsonb")) {
            return "Invalid JSON format in request payload.";
        }

        if (raw.contains("column \"path\" is of type ltree")) {
            return "Scope path must be a valid ltree value. Please ensure the hierarchy is valid.";
        }

        if (raw.contains("relation") && raw.contains("does not exist")) {
            return "Database schema is missing required tables. Ensure Flyway migrations ran.";
        }

        // Unmapped database errors must not leak SQL details to clients
        log.error("Unmapped data access error: {}", raw);
        return "Database operation failed.";
    }

    private String mapCheckConstraint(String constraint) {
        return switch (constraint) {
            case "chk_permission_key_format" ->
                    "Permission key must be in the format domain.resource.action (lowercase, underscores only).";
            case "chk_permission_domain_lowercase" ->
                    "Permission domain must be lowercase.";
            case "chk_permission_resource_lowercase" ->
                    "Permission resource must be lowercase.";
            case "chk_permission_action_lowercase" ->
                    "Permission action must be lowercase.";
            case "chk_scope_type" ->
                    "Invalid scope type. Allowed: GLOBAL, COUNTRY, REGION, ORG, DEPT, TEAM, PROJECT.";
            case "chk_scope_global_no_parent" ->
                    "GLOBAL scope cannot have a parent.";
            case "chk_scope_non_global_has_parent" ->
                    "Non-GLOBAL scopes must have a parent.";
            case "chk_closure_depth_non_negative" ->
                    "Scope closure depth must be non-negative.";
            case "chk_role_org_type" ->
                    "Invalid org type for role.";
            case "chk_role_name_format" ->
                    "Role name must start with a letter and contain only letters, numbers, and underscores.";
            case "chk_role_system_cannot_delete", "chk_role_system_cannot_deactivate" ->
                    "System roles cannot be deactivated.";
            case "chk_assignment_effect" ->
                    "Assignment effect must be ALLOW or DENY.";
            case "chk_assignment_subject_type" ->
                    "Assignment subject type must be USER, SERVICE, or GROUP.";
            case "chk_assignment_expiry_future" ->
                    "Assignment expiry must be in the future.";
            case "chk_assignment_revoke_consistency" ->
                    "Revocation requires both revoked_at and revoked_by.";
            case "chk_deny_permission_format" ->
                    "Deny rule permission key must be in the format domain.resource.action or use * wildcards.";
            case "chk_deny_reason_not_empty" ->
                    "Deny rule reason cannot be empty.";
            case "chk_deny_expiry_future" ->
                    "Deny rule expiry must be in the future.";
            case "chk_role_hierarchy_no_self_reference" ->
                    "Role cannot inherit from itself.";
            default -> null;
        };
    }

    private String rootCauseMessage(Throwable ex) {
        Throwable current = ex;
        Throwable next = ex;
        while (next != null) {
            current = next;
            next = current.getCause();
        }
        return current != null ? current.getMessage() : null;
    }

}
