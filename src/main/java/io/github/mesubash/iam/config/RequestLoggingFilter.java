package io.github.mesubash.iam.config;

import io.github.mesubash.iam.util.ClientIpResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * One line per request: method, path, status, duration, client IP and Origin, so CORS
 * preflights, rejections and auth calls are all visible. Only the path is logged: never the
 * query string, bodies, headers or cookies, so no credential or token reaches the log.
 * Turn it off with {@code logging.level.io.github.mesubash.iam.config.RequestLoggingFilter=WARN}.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !log.isInfoEnabled() || uri.startsWith("/actuator") || uri.startsWith("/docs")
                || uri.startsWith("/webjars");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long start = System.nanoTime();
        try {
            chain.doFilter(request, response);
        } finally {
            String origin = request.getHeader("Origin");
            log.info("{} {} -> {} ({}ms) ip={}{}", request.getMethod(), request.getRequestURI(),
                    response.getStatus(), (System.nanoTime() - start) / 1_000_000,
                    ClientIpResolver.resolve(request), origin != null ? " origin=" + origin : "");
        }
    }
}
