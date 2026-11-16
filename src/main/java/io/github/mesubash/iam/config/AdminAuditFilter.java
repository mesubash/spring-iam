package io.github.mesubash.iam.config;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.AdminAuditLog;
import io.github.mesubash.iam.authz.service.AdminAuditService;
import io.github.mesubash.iam.util.ClientIpResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Records every successful mutating call to the admin API (/api/v1/*) as an admin-audit row.
 * Sits after authentication in the security chain so the actor is known. Rejected calls (4xx/5xx)
 * changed nothing and are skipped, as are the POST-shaped reads of the decision API and the
 * user's own flows under /api/auth/* (login, MFA, sessions), which are not configuration changes.
 *
 * <p>Not a bean on purpose: a @Component filter would also be registered on the servlet chain,
 * where it would run outside the security context.
 */
@RequiredArgsConstructor
public class AdminAuditFilter extends OncePerRequestFilter {

    private static final Set<String> MUTATING = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final String ADMIN_API = "/api/v1/";
    private static final List<String> READS = List.of(
            "/api/v1/authorize", "/api/v1/effective-permissions", "/api/v1/filter-resources",
            "/api/v1/access-list", "/api/v1/token/");

    private final AdminAuditService adminAuditService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        filterChain.doFilter(request, response);

        String path = request.getRequestURI();
        if (!MUTATING.contains(request.getMethod()) || !path.startsWith(ADMIN_API)
                || READS.stream().anyMatch(path::startsWith) || response.getStatus() >= 400) {
            return;
        }

        AdminAuditLog.AdminAuditLogBuilder entry = AdminAuditLog.builder()
                .method(request.getMethod())
                .path(path)
                .status(response.getStatus())
                .ip(ClientIpResolver.resolve(request))
                .userAgent(request.getHeader("User-Agent"));
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            entry.actorId(principal.getId()).actorEmail(principal.getEmail());
        }
        adminAuditService.record(entry.build());
    }
}
