package io.github.mesubash.iam.authz.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.flywaydb.core.Flyway;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditPartitionService {

    private static final DateTimeFormatter PARTITION_FORMAT =
            DateTimeFormatter.ofPattern("yyyy_MM");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectProvider<Flyway> flywayProvider;

    @Value("${iam.audit.partitioning.enabled:true}")
    private boolean enabled;

    @Value("${iam.audit.partitioning.create-ahead-months:2}")
    private int createAheadMonths;

    @Value("${iam.audit.partitioning.timezone:UTC}")
    private String timezone;

    @PostConstruct
    public void initialize() {
        ensurePartitions();
    }

    @Scheduled(cron = "${iam.audit.partitioning.cron:0 15 0 * * *}")
    public void scheduledPartitionCheck() {
        ensurePartitions();
    }

    public void ensurePartitions() {
        if (!enabled) {
            return;
        }

        if (flywayProvider.getIfAvailable() == null) {
            log.warn("Flyway is not available; skipping audit partition creation");
            return;
        }

        if (!baseTableExists()) {
            log.warn("authorization_audit table does not exist yet; skipping partition creation");
            return;
        }

        ZoneId zoneId = resolveZoneId();
        YearMonth start = YearMonth.now(zoneId);

        int monthsToCreate = Math.max(createAheadMonths, 1);
        for (int i = 0; i < monthsToCreate; i++) {
            ensurePartition(start.plusMonths(i));
        }
    }

    private void ensurePartition(YearMonth month) {
        String partitionName = "authorization_audit_" + PARTITION_FORMAT.format(month);
        String existing = jdbcTemplate.queryForObject(
                "SELECT to_regclass(?)", String.class, partitionName);

        if (existing != null) {
            return;
        }

        LocalDate startDate = month.atDay(1);
        LocalDate endDate = month.plusMonths(1).atDay(1);

        String sql = String.format(
                "CREATE TABLE %s PARTITION OF authorization_audit " +
                        "FOR VALUES FROM ('%s') TO ('%s')",
                partitionName, startDate, endDate);

        try {
            jdbcTemplate.execute(sql);
            log.info("Created audit partition {}", partitionName);
        } catch (Exception e) {
            log.error("Failed to create audit partition {}", partitionName, e);
        }
    }

    private ZoneId resolveZoneId() {
        try {
            return ZoneId.of(timezone);
        } catch (DateTimeException e) {
            return ZoneId.of("UTC");
        }
    }

    private boolean baseTableExists() {
        String existing = jdbcTemplate.queryForObject(
                "SELECT to_regclass('authorization_audit')", String.class);
        return existing != null;
    }
}
