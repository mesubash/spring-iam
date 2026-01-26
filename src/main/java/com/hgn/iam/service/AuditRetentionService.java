package com.hgn.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.flywaydb.core.Flyway;

import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditRetentionService {

    private static final DateTimeFormatter PARTITION_FORMAT =
            DateTimeFormatter.ofPattern("yyyy_MM");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectProvider<Flyway> flywayProvider;

    @Value("${iam.audit.retention.enabled:true}")
    private boolean enabled;

    @Value("${iam.audit.retention.months:24}")
    private int retentionMonths;

    @Value("${iam.audit.retention.action:DROP}")
    private String action;

    @Scheduled(cron = "${iam.audit.retention.cron:0 30 1 * * *}")
    public void enforceRetention() {
        if (!enabled) {
            return;
        }

        if (flywayProvider.getIfAvailable() == null) {
            log.warn("Flyway is not available; skipping audit retention");
            return;
        }

        if (!baseTableExists()) {
            log.warn("authorization_audit table does not exist yet; skipping retention");
            return;
        }

        List<String> partitions = jdbcTemplate.queryForList(
                "SELECT c.relname " +
                        "FROM pg_class c " +
                        "JOIN pg_inherits i ON c.oid = i.inhrelid " +
                        "JOIN pg_class p ON i.inhparent = p.oid " +
                        "WHERE p.relname = 'authorization_audit'",
                String.class);

        YearMonth cutoff = YearMonth.now().minusMonths(retentionMonths);

        for (String partition : partitions) {
            YearMonth partitionMonth = parsePartitionMonth(partition);
            if (partitionMonth == null || !partitionMonth.isBefore(cutoff)) {
                continue;
            }

            if ("DETACH".equalsIgnoreCase(action)) {
                detachPartition(partition);
            } else {
                dropPartition(partition);
            }
        }
    }

    private YearMonth parsePartitionMonth(String name) {
        if (!name.startsWith("authorization_audit_")) {
            return null;
        }
        String suffix = name.substring("authorization_audit_".length());
        try {
            return YearMonth.parse(suffix, PARTITION_FORMAT);
        } catch (Exception e) {
            return null;
        }
    }

    private void detachPartition(String partition) {
        try {
            jdbcTemplate.execute("ALTER TABLE authorization_audit DETACH PARTITION " + partition);
            log.info("Detached audit partition {}", partition);
        } catch (Exception e) {
            log.error("Failed to detach audit partition {}", partition, e);
        }
    }

    private void dropPartition(String partition) {
        try {
            jdbcTemplate.execute("DROP TABLE IF EXISTS " + partition);
            log.info("Dropped audit partition {}", partition);
        } catch (Exception e) {
            log.error("Failed to drop audit partition {}", partition, e);
        }
    }

    private boolean baseTableExists() {
        String existing = jdbcTemplate.queryForObject(
                "SELECT to_regclass('authorization_audit')", String.class);
        return existing != null;
    }
}
