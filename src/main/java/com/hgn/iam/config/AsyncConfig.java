package com.hgn.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Slf4j
@Configuration
@EnableAsync
public class AsyncConfig {

    /**
     * Executor for audit log processing
     * Separate thread pool to avoid blocking authorization checks
     */
    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // Core pool size: Number of threads to keep alive
        executor.setCorePoolSize(2);

        // Max pool size: Maximum number of threads
        executor.setMaxPoolSize(5);

        // Queue capacity: Number of tasks to queue before rejecting
        executor.setQueueCapacity(1000);

        // Thread name prefix for debugging
        executor.setThreadNamePrefix("audit-");

        // Rejection policy: CallerRuns means the calling thread will execute
        // the task if queue is full (ensures no audit logs are lost)
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // Wait for all tasks to complete on shutdown
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);

        executor.initialize();

        log.info("Initialized audit executor: core={}, max={}, queue={}",
                executor.getCorePoolSize(),
                executor.getMaxPoolSize(),
                executor.getQueueCapacity());

        return executor;
    }

    /**
     * Executor for cache warming and maintenance tasks
     */
    @Bean(name = "cacheExecutor")
    public Executor cacheExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("cache-");
        executor.initialize();
        return executor;
    }
}
