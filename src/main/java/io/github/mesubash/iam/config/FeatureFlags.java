package io.github.mesubash.iam.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * Layer/module switches. Everything defaults to the simple baseline;
 * deployments scale up by flipping flags, never by forking code.
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "iam.features")
public class FeatureFlags {

    private boolean resourceGrants = false;   // per-instance ReBAC grants
    private boolean groups = false;           // subject groups
    private boolean serviceRegistry = false;  // per-service API keys + manifest sync
    private boolean oauth2 = false;           // social login (informational for now)
    private boolean breakGlass = false;       // emergency time-boxed elevation
    private boolean introspection = false;    // token introspection endpoint

    public Map<String, Boolean> asMap() {
        return Map.of(
                "resource-grants", resourceGrants,
                "groups", groups,
                "service-registry", serviceRegistry,
                "oauth2", oauth2,
                "break-glass", breakGlass,
                "introspection", introspection);
    }
}
