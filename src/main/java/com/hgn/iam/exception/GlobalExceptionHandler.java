package com.hgn.iam.exception;


import com.hgn.iam.dto.ErrorResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataAccessException;
import org.springframework.validation.FieldError;
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
     * Custom exception for authorization failures
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(
            UnauthorizedException ex, WebRequest request) {

        log.warn("Unauthorized access attempt: {}", ex.getMessage());

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    private String resolveDataAccessMessage(Throwable ex) {
        String raw = rootCauseMessage(ex);
        if (raw == null) {
            return "Database operation failed.";
        }

        Pattern scopeDepthPattern = Pattern.compile(
                "Scope depth (\\d+) does not match type (\\w+)\\. Expected depth: (\\d+)");
        Matcher matcher = scopeDepthPattern.matcher(raw);
        if (matcher.find()) {
            String actual = matcher.group(1);
            String type = matcher.group(2);
            String expected = matcher.group(3);
            return "Invalid scope hierarchy: type " + type + " must be at depth " + expected
                    + ", but depth " + actual + " was provided. "
                    + "Required hierarchy is GLOBAL -> COUNTRY -> REGION -> ORG -> DEPT -> TEAM -> PROJECT.";
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

        return raw;
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
            case "chk_role_system_cannot_delete" ->
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
