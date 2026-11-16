package io.github.mesubash.iam.util;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;

/**
 * Resolves and normalizes client IPs.
 *
 * <p>{@link #resolve} uses the RIGHTMOST X-Forwarded-For entry, not the leftmost: the reverse
 * proxy appends the address it actually saw, while everything to the left is client-supplied and
 * trivially spoofable (a spoofed leftmost entry would let a caller dodge per-IP rate limits and
 * forge audit IPs). This assumes exactly one trusted proxy in front of the service.
 *
 * <p>{@link #normalize} makes a value safe for a Postgres {@code inet} column. A rejected insert
 * poisons the whole transaction, so a bad IP (bracketed IPv6, a port, junk) must be turned into
 * {@code null} before it reaches the column; the IP is metadata and must never fail a login.
 */
public final class ClientIpResolver {

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] hops = xff.split(",");
            String last = normalize(hops[hops.length - 1]);
            if (last != null) {
                return last;
            }
        }
        return normalize(request.getRemoteAddr());
    }

    /** @return a bare, valid IP literal, or {@code null} if absent or not storable. */
    public static String normalize(String ip) {
        if (ip == null) {
            return null;
        }
        String s = ip.trim();
        if (s.startsWith("[")) {                       // [2001:db8::1] or [2001:db8::1]:443
            int end = s.indexOf(']');
            s = end > 0 ? s.substring(1, end) : s;
        } else {
            int colon = s.indexOf(':');                // 1.2.3.4:5678 (bare IPv6 has several colons)
            if (colon > 0 && s.indexOf(':', colon + 1) < 0) {
                s = s.substring(0, colon);
            }
        }
        // Charset guard keeps InetAddress from doing a DNS lookup on a hostname.
        if (s.isEmpty() || !s.matches("[0-9A-Fa-f:.]+")) {
            return null;
        }
        try {
            InetAddress.getByName(s);
            return s;
        } catch (Exception e) {
            return null;
        }
    }
}
