package io.github.mesubash.iam.config;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Nightly read-only drift check between the scope tree and its closure table.
 * Detects corruption from manual SQL or a partial migration before it becomes
 * mystery denies. Disabled by default ("-" cron); repair is a manual action.
 */
@Slf4j
@Component
public class ScopeReconciliationJob {

    @PersistenceContext
    private EntityManager entityManager;

    @Scheduled(cron = "${iam.integrity.reconciliation-cron:-}")
    @Transactional(readOnly = true)
    public void reconcile() {
        long expected = ((Number) entityManager
                .createNativeQuery("SELECT COALESCE(SUM(depth + 1), 0) FROM scopes")
                .getSingleResult()).longValue();
        long actual = ((Number) entityManager
                .createNativeQuery("SELECT COUNT(*) FROM scope_closure")
                .getSingleResult()).longValue();
        long missingSelfRows = ((Number) entityManager.createNativeQuery(
                "SELECT COUNT(*) FROM scopes s WHERE NOT EXISTS (" +
                "SELECT 1 FROM scope_closure c WHERE c.ancestor_id = s.id AND c.descendant_id = s.id)")
                .getSingleResult()).longValue();

        if (expected == actual && missingSelfRows == 0) {
            log.info("Scope reconciliation OK ({} closure rows)", actual);
            return;
        }
        log.error("SCOPE DRIFT: closure rows expected={} actual={}, scopes missing self-row={}. "
                + "Manual repair required.", expected, actual, missingSelfRows);
    }
}
