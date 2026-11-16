package io.github.mesubash.iam.authn.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Where the IAM may send a browser back to with a one-time code (OAuth and SSO alike):
 * exact scheme and host, the port when the entry names one, and whole normalized path
 * segments under the entry's path. Entries come from {@code app.frontend.allowed-redirect-uris}
 * plus {@code cors.allowed-origins}; with neither set, only {@code app.frontend.url}'s origin.
 */
@Component
public class RedirectAllowlist {

    private final List<URI> allowed;

    public RedirectAllowlist(@Value("${app.frontend.allowed-redirect-uris:}") String allowedRedirectUris,
                             @Value("${cors.allowed-origins:}") String extraAllowedRedirectUris,
                             @Value("${app.frontend.url:http://localhost:3000}") String frontendBaseUrl) {
        List<URI> parsed = parse(allowedRedirectUris + "," + extraAllowedRedirectUris);
        this.allowed = parsed.isEmpty() ? parse(frontendBaseUrl) : parsed;
    }

    public boolean isAllowed(String uri) {
        if (!StringUtils.hasText(uri)) {
            return false;
        }
        try {
            URI candidate = new URI(uri);
            return StringUtils.hasText(candidate.getScheme())
                    && allowed.stream().anyMatch(a -> isMatch(candidate, a));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private static List<URI> parse(String commaSeparated) {
        List<URI> uris = new ArrayList<>();
        if (commaSeparated == null) {
            return uris;
        }
        for (String part : commaSeparated.split(",")) {
            try {
                URI uri = new URI(part.trim());
                if (StringUtils.hasText(uri.getScheme()) && StringUtils.hasText(uri.getHost())) {
                    uris.add(uri);
                }
            } catch (URISyntaxException ignored) {
            }
        }
        return uris;
    }

    private static boolean isMatch(URI candidate, URI allowed) {
        if (!allowed.getScheme().equalsIgnoreCase(candidate.getScheme())) {
            return false;
        }
        if (!allowed.getHost().equalsIgnoreCase(candidate.getHost())) {
            return false;
        }
        if (allowed.getPort() != -1 && allowed.getPort() != candidate.getPort()) {
            return false;
        }
        String allowedPath = allowed.getPath();
        if (StringUtils.hasText(allowedPath) && !"/".equals(allowedPath)) {
            // Normalize first ("/cb/../admin") and match whole segments ("/cb" must not allow "/cb-x").
            String candidatePath = candidate.normalize().getPath() == null ? "" : candidate.normalize().getPath();
            String base = allowedPath.endsWith("/") ? allowedPath.substring(0, allowedPath.length() - 1) : allowedPath;
            if (!candidatePath.equals(base) && !candidatePath.startsWith(base + "/")) {
                return false;
            }
        }
        return true;
    }
}
