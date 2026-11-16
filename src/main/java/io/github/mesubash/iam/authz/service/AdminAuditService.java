package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.AdminAuditLog;
import io.github.mesubash.iam.authz.repository.AdminAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/** Persists admin-action audit rows off the request thread. Best-effort: a failed write is logged. */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuditService {

    private final AdminAuditRepository repository;

    @Async("auditExecutor")
    public void record(AdminAuditLog entry) {
        try {
            repository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to write admin audit row for {} {}: {}",
                    entry.getMethod(), entry.getPath(), e.getMessage());
        }
    }
}
