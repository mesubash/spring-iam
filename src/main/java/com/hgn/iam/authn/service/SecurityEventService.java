package com.hgn.iam.authn.service;

import com.hgn.iam.authn.entity.Identity;
import com.hgn.iam.authn.entity.SecurityEvent;
import com.hgn.iam.authn.entity.enums.SecurityEventType;
import com.hgn.iam.authn.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;

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
                    .ipAddress(ipAddress)
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
