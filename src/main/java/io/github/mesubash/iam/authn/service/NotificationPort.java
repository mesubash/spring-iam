package io.github.mesubash.iam.authn.service;

import org.springframework.scheduling.annotation.Async;

/**
 * Outbound notification seam. Deployments plug their own channel (SMTP,
 * webhook to a notification service, …) by providing a bean; the default
 * adapter only logs — fine for dev, useless for production.
 *
 * <p>Every call runs on {@code notificationExecutor}, never the request thread: callers
 * such as register invoke it inside their transaction, and a slow mail provider must not
 * hold that open or make the endpoint time out after the row is already written. The
 * caller never learns whether the send worked, so adapters log their own failures and
 * should still set connect/read timeouts on their HTTP or SMTP client.
 */
@Async("notificationExecutor")
public interface NotificationPort {

    void sendEmailVerification(String email, String token);

    void sendPasswordReset(String email, String token);

    void sendReactivation(String email, String token);

    /**
     * Security alert: the account was locked after too many failed logins. Default no-op so
     * existing adapters keep compiling; override it to actually notify the owner.
     */
    default void sendAccountLocked(String email) {
    }
}
