package io.github.mesubash.iam.authn.service;

/**
 * Outbound notification seam. Deployments plug their own channel (SMTP,
 * webhook to a notification service, …) by providing a bean; the default
 * adapter only logs — fine for dev, useless for production.
 */
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
