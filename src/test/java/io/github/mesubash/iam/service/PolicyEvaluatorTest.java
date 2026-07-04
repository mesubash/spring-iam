package io.github.mesubash.iam.service;

import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.service.PolicyEvaluator;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyEvaluatorTest {

    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    @Test
    void evaluatesAnyConditionWithSubjectMatch() {
        Map<String, Object> condition = Map.of(
                "any", List.of(
                        Map.of("field", "subject", "op", "eq", "value", "user_1"),
                        Map.of("field", "resource.ownerId", "op", "eq", "value", "user_2")
                )
        );

        AuthorizationRequest request = baseRequest("user_1");
        assertTrue(evaluator.evaluate(condition, request));
    }

    @Test
    void evaluatesAllConditionWithContextMatch() {
        Map<String, Object> condition = Map.of(
                "all", List.of(
                        Map.of("field", "context.ipAddress", "op", "eq", "value", "10.0.0.1"),
                        Map.of("field", "resource.metadata.ownerId", "op", "eq", "value", "$subject")
                )
        );

        AuthorizationRequest request = baseRequest("user_9");
        request.getContext().setIpAddress("10.0.0.1");
        request.getResource().setMetadata(Map.of("ownerId", "user_9"));

        assertTrue(evaluator.evaluate(condition, request));
    }

    @Test
    void evaluatesNotCondition() {
        Map<String, Object> condition = Map.of(
                "not", Map.of("field", "context.userAgent", "op", "contains", "value", "Bot")
        );

        AuthorizationRequest request = baseRequest("user_1");
        request.getContext().setUserAgent("Mozilla/5.0");

        assertTrue(evaluator.evaluate(condition, request));
    }

    @Test
    void evaluatesBeforeAfterInstant() {
        Map<String, Object> condition = Map.of(
                "all", List.of(
                        Map.of("field", "context.timestamp", "op", "after",
                                "value", Instant.now().minusSeconds(60).toString()),
                        Map.of("field", "context.timestamp", "op", "before",
                                "value", Instant.now().plusSeconds(60).toString())
                )
        );

        AuthorizationRequest request = baseRequest("user_1");
        request.getContext().setTimestamp(Instant.now());

        assertTrue(evaluator.evaluate(condition, request));
    }

    @Test
    void failsWhenRequiredFieldMissing() {
        Map<String, Object> condition = Map.of(
                "all", List.of(
                        Map.of("field", "resource.metadata.ownerId", "op", "eq", "value", "$subject")
                )
        );

        AuthorizationRequest request = baseRequest("user_1");
        request.getResource().setMetadata(Map.of());

        assertFalse(evaluator.evaluate(condition, request));
    }

    private AuthorizationRequest baseRequest(String subject) {
        return AuthorizationRequest.builder()
                .subject(subject)
                .permission("order.order.approve")
                .resource(AuthorizationRequest.ResourceContext.builder()
                        .type("ORDER")
                        .id("ORD-1")
                        .scopeId(UUID.randomUUID())
                        .build())
                .context(AuthorizationRequest.RequestContext.builder()
                        .timestamp(Instant.now())
                        .build())
                .build();
    }
}