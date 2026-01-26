package com.hgn.iam.service;

import com.hgn.iam.dto.AuthorizationRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class PolicyEvaluator {

    public boolean evaluate(Map<String, Object> conditions, AuthorizationRequest request) {
        if (conditions == null || conditions.isEmpty()) {
            return true;
        }

        return evaluateNode(conditions, request);
    }

    @SuppressWarnings("unchecked")
    private boolean evaluateNode(Object node, AuthorizationRequest request) {
        if (node instanceof Map<?, ?> map) {
            if (map.containsKey("all")) {
                Object all = map.get("all");
                if (!(all instanceof Collection<?> items)) {
                    return false;
                }
                for (Object item : items) {
                    if (!evaluateNode(item, request)) {
                        return false;
                    }
                }
                return true;
            }
            if (map.containsKey("any")) {
                Object any = map.get("any");
                if (!(any instanceof Collection<?> items)) {
                    return false;
                }
                for (Object item : items) {
                    if (evaluateNode(item, request)) {
                        return true;
                    }
                }
                return false;
            }
            if (map.containsKey("not")) {
                return !evaluateNode(map.get("not"), request);
            }

            String field = getString(map.get("field"));
            String op = getString(map.get("op"));
            Object expected = map.get("value");
            if (field == null || op == null) {
                return false;
            }
            Object actual = resolveField(field, request);
            Object resolvedExpected = resolveValue(expected, request);
            return evaluateLeaf(op, actual, resolvedExpected);
        }

        return false;
    }

    private boolean evaluateLeaf(String op, Object actual, Object expected) {
        return switch (op) {
            case "eq" -> equalsValue(actual, expected);
            case "neq" -> !equalsValue(actual, expected);
            case "in" -> inCollection(actual, expected);
            case "not_in" -> !inCollection(actual, expected);
            case "contains" -> containsValue(actual, expected);
            case "exists" -> actual != null;
            case "gt" -> compareNumbers(actual, expected) > 0;
            case "gte" -> compareNumbers(actual, expected) >= 0;
            case "lt" -> compareNumbers(actual, expected) < 0;
            case "lte" -> compareNumbers(actual, expected) <= 0;
            case "regex" -> matchesRegex(actual, expected);
            case "before" -> compareInstants(actual, expected) < 0;
            case "after" -> compareInstants(actual, expected) > 0;
            default -> false;
        };
    }

    private Object resolveValue(Object value, AuthorizationRequest request) {
        if (value instanceof String str && str.startsWith("$")) {
            return resolveField(str.substring(1), request);
        }
        return value;
    }

    private Object resolveField(String path, AuthorizationRequest request) {
        if (path == null) {
            return null;
        }

        if ("subject".equals(path)) {
            return request.getSubject();
        }
        if ("permission".equals(path)) {
            return request.getPermission();
        }

        if (path.startsWith("resource.")) {
            return resolveResourceField(path.substring("resource.".length()), request);
        }

        if (path.startsWith("context.")) {
            return resolveContextField(path.substring("context.".length()), request);
        }

        return null;
    }

    private Object resolveResourceField(String path, AuthorizationRequest request) {
        AuthorizationRequest.ResourceContext resource = request.getResource();
        if (resource == null) {
            return null;
        }
        return switch (path) {
            case "type" -> resource.getType();
            case "id" -> resource.getId();
            case "scopeId" -> resource.getScopeId() != null ? resource.getScopeId().toString() : null;
            default -> {
                if (path.startsWith("metadata.") && resource.getMetadata() != null) {
                    String key = path.substring("metadata.".length());
                    yield resource.getMetadata().get(key);
                }
                yield resource.getMetadata() != null ? resource.getMetadata().get(path) : null;
            }
        };
    }

    private Object resolveContextField(String path, AuthorizationRequest request) {
        AuthorizationRequest.RequestContext context = request.getContext();
        if (context == null) {
            return null;
        }
        return switch (path) {
            case "timestamp" -> context.getTimestamp();
            case "ipAddress" -> context.getIpAddress();
            case "userAgent" -> context.getUserAgent();
            case "sessionId" -> context.getSessionId();
            case "requestId" -> context.getRequestId();
            default -> {
                if (path.startsWith("additional.") && context.getAdditionalContext() != null) {
                    String key = path.substring("additional.".length());
                    yield context.getAdditionalContext().get(key);
                }
                yield context.getAdditionalContext() != null
                        ? context.getAdditionalContext().get(path)
                        : null;
            }
        };
    }

    private boolean equalsValue(Object actual, Object expected) {
        if (actual == null || expected == null) {
            return actual == expected;
        }
        return actual.toString().equals(expected.toString());
    }

    private boolean inCollection(Object actual, Object expected) {
        if (actual == null || expected == null) {
            return false;
        }
        if (expected instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (equalsValue(actual, item)) {
                    return true;
                }
            }
            return false;
        }
        String expectedString = expected.toString();
        String[] parts = expectedString.split(",");
        for (String part : parts) {
            if (equalsValue(actual, part.trim())) {
                return true;
            }
        }
        return false;
    }

    private boolean containsValue(Object actual, Object expected) {
        if (actual == null || expected == null) {
            return false;
        }
        if (actual instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (equalsValue(item, expected)) {
                    return true;
                }
            }
            return false;
        }
        return actual.toString().contains(expected.toString());
    }

    private int compareNumbers(Object actual, Object expected) {
        Double left = toNumber(actual);
        Double right = toNumber(expected);
        if (left == null || right == null) {
            return 0;
        }
        return Double.compare(left, right);
    }

    private Double toNumber(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private boolean matchesRegex(Object actual, Object expected) {
        if (actual == null || expected == null) {
            return false;
        }
        try {
            return actual.toString().matches(expected.toString());
        } catch (Exception e) {
            return false;
        }
    }

    private int compareInstants(Object actual, Object expected) {
        Instant left = toInstant(actual);
        Instant right = toInstant(expected);
        if (left == null || right == null) {
            return 0;
        }
        return left.compareTo(right);
    }

    private Instant toInstant(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof java.util.Date date) {
            return date.toInstant();
        }
        if (value instanceof Long longVal) {
            return Instant.ofEpochMilli(longVal);
        }
        String text = value.toString();
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException ignored) {
        }
        try {
            LocalDateTime dateTime = LocalDateTime.parse(text);
            return dateTime.atZone(ZoneId.of("UTC")).toInstant();
        } catch (DateTimeParseException ignored) {
        }
        try {
            LocalDate date = LocalDate.parse(text);
            return date.atStartOfDay(ZoneId.of("UTC")).toInstant();
        } catch (DateTimeException ignored) {
        }
        return null;
    }

    private String getString(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
