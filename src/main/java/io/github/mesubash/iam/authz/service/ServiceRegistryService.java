package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.ServiceClient;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import io.github.mesubash.iam.authz.repository.ServiceClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Consumer service registry: per-service API keys and permission manifest
 * sync. Permissions live in the consumer's codebase and are pushed on
 * deploy — keys are upserted, never renamed; missing keys get deprecated.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ServiceRegistryService {

    private final ServiceClientRepository serviceClientRepository;
    private final PermissionRepository permissionRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public record RegisteredService(ServiceClient service, String rawApiKey) {}

    public record SyncResult(int created, int unchanged, int deprecated) {}

    @Transactional
    public RegisteredService register(String name, String displayName, List<String> ownedDomains) {
        serviceClientRepository.findByName(name).ifPresent(existing -> {
            throw new IllegalArgumentException("Service already registered: " + name);
        });

        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        String rawKey = "iamsvc_" + Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);

        ServiceClient service = serviceClientRepository.save(ServiceClient.builder()
                .name(name)
                .displayName(displayName != null ? displayName : name)
                .ownedDomains(ownedDomains != null ? ownedDomains : List.of())
                .apiKeyHash(sha256(rawKey))
                .createdAt(Instant.now())
                .build());

        log.info("Registered service '{}' owning domains {}", name, service.getOwnedDomains());
        return new RegisteredService(service, rawKey);
    }

    /**
     * Idempotent manifest sync, restricted to the service's owned domains.
     * deprecateMissing marks owned keys absent from the manifest as
     * deprecated — permission keys are immutable contracts, never deleted.
     */
    @Transactional
    public SyncResult syncPermissions(String serviceName, List<Map<String, String>> permissions,
                                      boolean deprecateMissing) {
        ServiceClient service = serviceClientRepository.findByName(serviceName)
                .orElseThrow(() -> new IllegalArgumentException("Service not found: " + serviceName));

        Set<String> manifestKeys = new HashSet<>();
        int created = 0;
        int unchanged = 0;

        for (Map<String, String> entry : permissions) {
            String key = entry.get("key");
            if (key == null || !key.matches("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){2,5}$")) {
                throw new IllegalArgumentException("Invalid permission key: " + key);
            }
            String[] segments = key.split("\\.");
            String domain = segments[0];
            if (!service.getOwnedDomains().contains(domain)) {
                throw new IllegalArgumentException(
                        "Service '" + serviceName + "' does not own domain '" + domain + "'");
            }
            manifestKeys.add(key);

            if (permissionRepository.existsByKey(key)) {
                unchanged++;
            } else {
                permissionRepository.save(Permission.builder()
                        .key(key)
                        .domain(domain)
                        .resource(String.join(".",
                                java.util.Arrays.copyOfRange(segments, 1, segments.length - 1)))
                        .action(segments[segments.length - 1])
                        .description(entry.get("description"))
                        .createdBy("service:" + serviceName)
                        .build());
                created++;
            }
        }

        int deprecated = 0;
        if (deprecateMissing) {
            for (String domain : service.getOwnedDomains()) {
                for (Permission p : permissionRepository.findByDomain(domain)) {
                    if (!manifestKeys.contains(p.getKey()) && !Boolean.TRUE.equals(p.getIsDeprecated())) {
                        p.setIsDeprecated(true);
                        permissionRepository.save(p);
                        deprecated++;
                    }
                }
            }
        }

        log.info("Manifest sync for '{}': {} created, {} unchanged, {} deprecated",
                serviceName, created, unchanged, deprecated);
        return new SyncResult(created, unchanged, deprecated);
    }

    @Transactional(readOnly = true)
    public List<ServiceClient> listAll() {
        return serviceClientRepository.findAll();
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
