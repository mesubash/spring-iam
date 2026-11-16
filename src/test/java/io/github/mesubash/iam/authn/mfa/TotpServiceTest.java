package io.github.mesubash.iam.authn.mfa;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class TotpServiceTest {

    private final TotpService totp = new TotpService();

    /** Same RFC 6238 computation as the service — produces a currently-valid code. */
    static String codeFor(String base32Secret, long step) throws Exception {
        byte[] key = base32Decode(base32Secret);
        byte[] data = ByteBuffer.allocate(8).putLong(step).array();
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = mac.doFinal(data);
        int offset = hash[hash.length - 1] & 0xF;
        int binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
        return String.format("%06d", binary % 1_000_000);
    }

    private static byte[] base32Decode(String s) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : s.toCharArray()) {
            buffer = (buffer << 5) | alphabet.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    @Test
    void accepts_valid_current_code_and_returns_step() throws Exception {
        String secret = totp.newSecret();
        long step = System.currentTimeMillis() / 1000 / 30;
        Optional<Long> matched = totp.verify(secret, codeFor(secret, step), null);
        assertThat(matched).contains(step);
    }

    @Test
    void rejects_replayed_step() throws Exception {
        String secret = totp.newSecret();
        long step = System.currentTimeMillis() / 1000 / 30;
        String code = codeFor(secret, step);
        assertThat(totp.verify(secret, code, null)).isPresent();
        // Same code again with lastStep recorded → replay guard rejects
        assertThat(totp.verify(secret, code, step)).isEmpty();
    }

    @Test
    void rejects_wrong_code_and_bad_shapes() {
        String secret = totp.newSecret();
        assertThat(totp.verify(secret, "000001", null)).isEmpty();  // (1-in-1M flake accepted)
        assertThat(totp.verify(secret, "12345", null)).isEmpty();   // wrong length
        assertThat(totp.verify(secret, null, null)).isEmpty();
    }

    @Test
    void provisioning_uri_is_otpauth_shaped() {
        String uri = totp.provisioningUri("Example", "a@b.com", "SECRET234");
        assertThat(uri).startsWith("otpauth://totp/Example:a%40b.com?secret=SECRET234")
                .contains("issuer=Example").contains("digits=6").contains("period=30");
    }
}
