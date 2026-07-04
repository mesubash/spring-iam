package io.github.mesubash.iam.authn.service.impl;

import io.github.mesubash.iam.authn.service.NotificationPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Dev default: logs the token instead of sending anything. */
@Configuration
@Slf4j
public class LogNotificationAdapter {

    @Bean
    @ConditionalOnMissingBean(NotificationPort.class)
    public NotificationPort logNotificationPort() {
        return new NotificationPort() {
            @Override
            public void sendEmailVerification(String email, String token) {
                log.warn("DEV notification adapter — email verification for {}: token={}", email, token);
            }

            @Override
            public void sendPasswordReset(String email, String token) {
                log.warn("DEV notification adapter — password reset for {}: token={}", email, token);
            }

            @Override
            public void sendReactivation(String email, String token) {
                log.warn("DEV notification adapter — reactivation for {}: token={}", email, token);
            }
        };
    }
}
