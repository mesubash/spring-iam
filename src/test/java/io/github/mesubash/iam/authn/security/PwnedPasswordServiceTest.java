package io.github.mesubash.iam.authn.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PwnedPasswordServiceTest {

    private static final String BODY = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
            + "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n"
            + "011053FD0102E94D6AE2F8B83D76FAF94F6:12";

    @Test
    void matchesSuffixWithACount() {
        assertThat(PwnedPasswordService.listed(BODY, "0018A45C4D1DEF81644B54AB7F969B88D65")).isTrue();
        assertThat(PwnedPasswordService.listed(BODY, "011053fd0102e94d6ae2f8b83d76faf94f6")).isTrue();
    }

    @Test
    void ignoresPaddingRowsAndMisses() {
        assertThat(PwnedPasswordService.listed(BODY, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC")).isFalse();
        assertThat(PwnedPasswordService.listed(BODY, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")).isFalse();
    }

    @Test
    void disabledByDefaultNeverCallsOut() {
        assertThat(new PwnedPasswordService().isBreached("password1")).isFalse();
    }
}
