package io.github.mesubash.iam.config;

import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.repository.RolePermissionRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Startup invariant check. Detects the corruption class that otherwise
 * surfaces as mystery denies (dangling refs, hollow system roles, broken
 * scope tree). With fail-on-error the app refuses to start on a broken DB.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IntegrityValidator {

    private final ScopeRepository scopeRepository;
    private final RoleRepository roleRepository;
    private final RolePermissionRepository rolePermissionRepository;

    @Value("${iam.integrity.fail-on-error:false}")
    private boolean failOnError;

    @PersistenceContext
    private EntityManager entityManager;

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
        List<String> problems = new ArrayList<>();

        long rootCount = count("SELECT COUNT(s) FROM Scope s WHERE s.parentId IS NULL");
        if (rootCount != 1) {
            problems.add("Expected exactly one root scope, found " + rootCount);
        }

        long danglingScopes = count(
                "SELECT COUNT(a) FROM Assignment a WHERE a.active = true " +
                "AND a.scopeId NOT IN (SELECT s.id FROM Scope s)");
        if (danglingScopes > 0) {
            problems.add(danglingScopes + " active assignment(s) reference a missing scope");
        }

        long danglingRoles = count(
                "SELECT COUNT(a) FROM Assignment a WHERE a.active = true " +
                "AND a.roleId NOT IN (SELECT r.id FROM Role r)");
        if (danglingRoles > 0) {
            problems.add(danglingRoles + " active assignment(s) reference a missing role");
        }

        long closureRows = count("SELECT COUNT(c) FROM ScopeClosure c");
        long scopeRows = count("SELECT COUNT(s) FROM Scope s");
        if (closureRows < scopeRows) {
            problems.add("scope_closure has fewer rows (" + closureRows
                    + ") than scopes (" + scopeRows + ") — self-rows missing");
        }

        for (Role role : roleRepository.findAll()) {
            if (Boolean.TRUE.equals(role.getIsSystemRole())
                    && rolePermissionRepository.findPermissionsByRoleIds(java.util.Set.of(role.getId())).isEmpty()) {
                problems.add("System role '" + role.getName() + "' has no permissions (hollow)");
            }
        }

        if (problems.isEmpty()) {
            log.info("Integrity check passed ({} scopes, {} closure rows)", scopeRows, closureRows);
            return;
        }

        problems.forEach(p -> log.error("INTEGRITY: {}", p));
        if (failOnError) {
            throw new IllegalStateException(
                    "Integrity check failed with " + problems.size() + " problem(s); refusing to start");
        }
    }

    private long count(String jpql) {
        return entityManager.createQuery(jpql, Long.class).getSingleResult();
    }
}
