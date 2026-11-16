package io.github.mesubash.iam.authn.mfa;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s step). No external dependency.
 * Verification accepts a +/-1 step window and reports the matched counter so
 * the caller can enforce replay protection.
 */
@Service
public class TotpService {

    private static final int DIGITS = 6;
    private static final int STEP_SECONDS = 30;
    private static final int WINDOW = 1; // +/-1 step (~30s drift)
    private static final SecureRandom RNG = new SecureRandom();
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    /** New random Base32 secret (160 bits). */
    public String newSecret() {
        byte[] bytes = new byte[20];
        RNG.nextBytes(bytes);
        return base32Encode(bytes);
    }

    public String provisioningUri(String issuer, String accountEmail, String base32Secret) {
        String label = urlEncode(issuer) + ":" + urlEncode(accountEmail);
        return "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(issuer)
                + "&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    /**
     * Verify a code. Returns the matched step counter (for replay storage) when
     * valid and strictly greater than lastStep; empty otherwise.
     */
    public Optional<Long> verify(String base32Secret, String code, Long lastStep) {
        if (code == null || code.length() != DIGITS) return Optional.empty();
        byte[] key = base32Decode(base32Secret);
        long currentStep = System.currentTimeMillis() / 1000L / STEP_SECONDS;
        for (long s = currentStep - WINDOW; s <= currentStep + WINDOW; s++) {
            if (lastStep != null && s <= lastStep) continue; // replay guard
            if (MessageDigest.isEqual(generate(key, s).getBytes(), code.getBytes())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    private String generate(byte[] key, long step) {
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(step).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    // --- Base32 (RFC 4648, no padding) ---
    private static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32[(buffer >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(BASE32[(buffer << (5 - bits)) & 0x1F]);
        return sb.toString();
    }

    private static byte[] base32Decode(String s) {
        s = s.trim().replace("=", "").toUpperCase();
        int buffer = 0, bits = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : s.toCharArray()) {
            int val = new String(BASE32).indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
    }
}
