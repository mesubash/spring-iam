package io.github.mesubash.iam.authn.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Any adapter a deployment plugs in runs off the request thread, without opting in. */
@SpringBootTest
class NotificationPortAsyncTest {

    static final CompletableFuture<String> SENT_ON = new CompletableFuture<>();

    @TestConfiguration
    static class RecordingAdapter {
        @Bean
        @Primary
        NotificationPort recordingNotificationPort() {
            return new NotificationPort() {
                @Override public void sendEmailVerification(String email, String token) {}
                @Override public void sendReactivation(String email, String token) {}
                @Override public void sendPasswordReset(String email, String token) {
                    SENT_ON.complete(Thread.currentThread().getName());
                }
            };
        }
    }

    @Autowired private NotificationPort notificationPort;

    @Test
    void sendsRunOnTheNotificationExecutor() throws Exception {
        notificationPort.sendPasswordReset("a@example.com", "token");
        assertThat(SENT_ON.get(5, TimeUnit.SECONDS)).startsWith("notify-");
    }
}
