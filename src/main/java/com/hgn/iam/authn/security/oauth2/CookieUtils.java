package com.hgn.iam.authn.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Utility helpers for working with HTTP cookies in the OAuth2 flow.
 */
public final class CookieUtils {

    private CookieUtils() {
    }

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return Optional.of(cookie);
            }
        }
        return Optional.empty();
    }

    public static void addCookie(
            HttpServletResponse response,
            String name,
            String value,
            int maxAgeSeconds,
            boolean secure,
            String domain) {

        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "Lax");
        if (StringUtils.hasText(domain) && !"localhost".equals(domain)) {
            cookie.setDomain(domain);
        }
        response.addCookie(cookie);
    }

    public static void deleteCookie(
            HttpServletRequest request,
            HttpServletResponse response,
            String name,
            boolean secure,
            String domain) {

        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return;
        }

        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                cookie.setHttpOnly(true);
                cookie.setSecure(secure);
                cookie.setAttribute("SameSite", "Lax");
                if (StringUtils.hasText(domain) && !"localhost".equals(domain)) {
                    cookie.setDomain(domain);
                }
                response.addCookie(cookie);
            }
        }
    }

    public static String serialize(Object object) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(object));
    }

    public static String serializeAndSign(Object object, String secret) {
        String payload = serialize(object);
        return sign(payload, secret);
    }

    @SuppressWarnings("unchecked")
    public static <T> T deserialize(String value) {
        return (T) SerializationUtils.deserialize(Base64.getUrlDecoder().decode(value));
    }

    @SuppressWarnings("unchecked")
    public static <T> T deserializeSigned(String value, String secret) {
        String payload = verifyAndExtract(value, secret);
        if (payload == null) {
            return null;
        }
        return (T) SerializationUtils.deserialize(Base64.getUrlDecoder().decode(payload));
    }

    public static String signRaw(String value, String secret) {
        return sign(value, secret);
    }

    public static String verifySignedRaw(String value, String secret) {
        return verifyAndExtract(value, secret);
    }

    private static String sign(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] signature = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String encodedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            return payload + "." + encodedSig;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign cookie payload", e);
        }
    }

    private static String verifyAndExtract(String signedValue, String secret) {
        if (!StringUtils.hasText(signedValue)) {
            return null;
        }
        int idx = signedValue.lastIndexOf('.');
        if (idx <= 0) {
            return null;
        }
        String payload = signedValue.substring(0, idx);
        String sig = signedValue.substring(idx + 1);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String expectedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(expected);
            if (!expectedSig.equals(sig)) {
                return null;
            }
            return payload;
        } catch (Exception e) {
            return null;
        }
    }
}
