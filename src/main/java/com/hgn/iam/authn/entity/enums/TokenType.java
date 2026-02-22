package com.hgn.iam.authn.entity.enums;


/**
 * Enum representing different types of authentication tokens
 */
public enum TokenType {
    /**
     * Refresh token for obtaining new access tokens
     */
    REFRESH,

    /**
     * Token for password reset functionality
     */
    PASSWORD_RESET,

    /**
     * Token for email verification
     */
    EMAIL_VERIFICATION,

    /**
     * Token for account reactivation
     */
    ACCOUNT_REACTIVATION
}
