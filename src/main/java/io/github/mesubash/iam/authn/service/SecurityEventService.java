package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.util.ClientIpResolver;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.SecurityEvent;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;
    private final IdentityRepository identityRepository;

    /** Log by identity id, for callers (e.g. SessionService) that don't hold the entity. */
    @Async
    public void logEvent(UUID identityId, SecurityEventType eventType, Map<String, Object> metadata) {
        try {
            securityEventRepository.save(SecurityEvent.builder()
                    .identity(identityRepository.getReferenceById(identityId))
                    .eventType(eventType)
                    .metadata(metadata == null ? Map.of() : metadata)
                    .build());
        } catch (Exception e) {
            log.error("Failed to log security event {} for identity {}: {}", eventType, identityId, e.getMessage());
        }
    }

    @Async
    public void logEvent(Identity identity, SecurityEventType eventType, String ipAddress, String userAgent) {
        logEvent(identity, eventType, ipAddress, userAgent, Map.of());
    }

    @Async
    public void logEvent(Identity identity, SecurityEventType eventType, String ipAddress, String userAgent,
                         Map<String, Object> metadata) {
        try {
            SecurityEvent event = SecurityEvent.builder()
                    .identity(identity)
                    .eventType(eventType)
                    .ipAddress(ClientIpResolver.normalize(ipAddress))
                    .userAgent(userAgent)
                    .metadata(metadata)
                    .build();
            securityEventRepository.save(event);
            log.debug("Security event logged: {} for identity {}", eventType, identity.getId());
        } catch (Exception e) {
            log.error("Failed to log security event {} for identity {}: {}",
                    eventType, identity.getId(), e.getMessage());
        }
    }
}
