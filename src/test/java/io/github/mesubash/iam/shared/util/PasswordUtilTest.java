package io.github.mesubash.iam.shared.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordUtilTest {

    @Test
    void acceptsLetterAndDigitWithinBounds() {
        assertThat(PasswordUtil.policyViolation("abcd1234")).isNull();
        assertThat(PasswordUtil.policyViolation("a1".repeat(36))).isNull();
    }

    @Test
    void rejectsTooShortTooLongOrSingleClass() {
        assertThat(PasswordUtil.policyViolation(null)).contains("at least");
        assertThat(PasswordUtil.policyViolation("abc1234")).contains("at least");
        assertThat(PasswordUtil.policyViolation("a1".repeat(36) + "x")).contains("at most");
        assertThat(PasswordUtil.policyViolation("aaaaaaaa")).contains("letter and one digit");
        assertThat(PasswordUtil.policyViolation("12345678")).contains("letter and one digit");
    }
}
