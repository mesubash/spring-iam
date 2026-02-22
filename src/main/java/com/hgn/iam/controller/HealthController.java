package com.hgn.iam.controller;


import com.hgn.iam.authz.service.CacheService;
import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/api/v1/health")
@RequiredArgsConstructor
@Tag(name = "Health", description = "Health check and monitoring")
public class HealthController {

    private final CacheService cacheService;
    private final MeterRegistry meterRegistry;

    @GetMapping("/cache-stats")
    public ResponseEntity<CacheService.CacheStats> getCacheStats() {
        return ResponseEntity.ok(cacheService.getCacheStats());
    }

    @GetMapping("/metrics")
    public ResponseEntity<Map<String, Object>> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        // Authorization metrics
        metrics.put("authorization.allow.total",
                meterRegistry.counter("authorization.decision.allow").count());
        metrics.put("authorization.deny.total",
                meterRegistry.counter("authorization.decision.deny").count());
        metrics.put("authorization.cache.hit.total",
                meterRegistry.counter("authorization.cache.hit").count());
        metrics.put("authorization.cache.miss.total",
                meterRegistry.counter("authorization.cache.miss").count());

        // Timer statistics
        var timer = meterRegistry.timer("authorization.check.duration");
        metrics.put("authorization.avg.latency.ms", timer.mean(TimeUnit.MILLISECONDS));
        metrics.put("authorization.max.latency.ms", timer.max(TimeUnit.MILLISECONDS));
        metrics.put("authorization.total.checks", timer.count());

        // Cache statistics
        metrics.put("cache.stats", cacheService.getCacheStats());

        return ResponseEntity.ok(metrics);
    }
}

/**
 * Custom health indicator for database
 */
@Configuration
@RequiredArgsConstructor
class HealthIndicatorsConfig {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    @Bean
    HealthIndicator redisHealthIndicator() {
        return () -> {
            try {
                redisTemplate.opsForValue().get("health-check");
                return Health.up()
                        .withDetail("redis", "Connection successful")
                        .build();
            } catch (Exception e) {
                return Health.down(e)
                        .withDetail("redis", "Connection failed")
                        .build();
            }
        };
    }

    @Bean
    HealthIndicator databaseHealthIndicator() {
        return () -> {
            try {
                jdbcTemplate.queryForObject("SELECT 1", Integer.class);
                return Health.up()
                        .withDetail("database", "Connection successful")
                        .build();
            } catch (Exception e) {
                return Health.down(e)
                        .withDetail("database", "Connection failed")
                        .build();
            }
        };
    }
}
