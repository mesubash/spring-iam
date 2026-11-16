package io.github.mesubash.iam.authn.security;

import io.github.mesubash.iam.shared.exception.BadRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Checks a password against the Have I Been Pwned "Pwned Passwords" range API with
 * k-anonymity: only the first 5 hex chars of its SHA-1 leave the service, never the
 * password. Off by default ({@code iam.password.breach-check.enabled}). Fail-open: if
 * the API is slow or down, the password is allowed rather than blocking the user.
 */
@Slf4j
@Service
public class PwnedPasswordService {

    private static final String RANGE_API = "https://api.pwnedpasswords.com/range/";
    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    @Value("${iam.password.breach-check.enabled:false}")
    private boolean enabled;

    public void rejectIfBreached(String password) {
        if (isBreached(password)) {
            throw new BadRequestException("This password appears in known data breaches, so attackers try it "
                    + "early. It is not about length or complexity: choose a different one.");
        }
    }

    boolean isBreached(String password) {
        if (!enabled || password == null || password.isEmpty()) {
            return false;
        }
        try {
            String sha1 = HexFormat.of().withUpperCase().formatHex(
                    MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8)));
            HttpRequest request = HttpRequest.newBuilder(URI.create(RANGE_API + sha1.substring(0, 5)))
                    .timeout(TIMEOUT)
                    .header("Add-Padding", "true")
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200 && listed(response.body(), sha1.substring(5));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            log.warn("Breach check unavailable, allowing password: {}", e.getMessage());
            return false;
        }
    }

    /** True if the range response lists {@code suffix} with a non-zero count (padding rows are 0). */
    static boolean listed(String rangeBody, String suffix) {
        for (String line : rangeBody.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && suffix.equalsIgnoreCase(line.substring(0, colon).trim())) {
                return !line.substring(colon + 1).trim().equals("0");
            }
        }
        return false;
    }
}
