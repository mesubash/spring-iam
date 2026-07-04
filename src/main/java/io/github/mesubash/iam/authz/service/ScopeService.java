package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Scope;
import io.github.mesubash.iam.authz.entity.ScopeType;
import io.github.mesubash.iam.authz.repository.ScopeClosureRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import io.github.mesubash.iam.authz.repository.ScopeTypeRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScopeService {

    private static final Pattern CODE_PATTERN = Pattern.compile("^[A-Za-z0-9_]{1,50}$");

    private final ScopeRepository scopeRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final ScopeTypeRepository scopeTypeRepository;
    private final CacheService cacheService;

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional(readOnly = true)
    public List<Scope> getAllActive() {
        return scopeRepository.findAllActive();
    }

    @Transactional(readOnly = true)
    public List<Scope> getByType(String type) {
        return scopeRepository.findByType(type);
    }

    @Transactional(readOnly = true)
    public Optional<Scope> getById(UUID id) {
        return scopeRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Scope getRoot() {
        return scopeRepository.findRoot()
                .orElseThrow(() -> new IllegalStateException("ROOT scope missing — seed corrupted"));
    }

    @Transactional(readOnly = true)
    public List<Scope> getDescendants(UUID scopeId) {
        Scope scope = scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));
        return scopeRepository.findDescendants(scope.getPath());
    }

    /**
     * Creates a child scope. Levels are deployment-defined: with an empty
     * scope_types registry any type label nests anywhere; with rows present
     * the type and its parent are validated against the registry.
     */
    @Transactional
    public Scope create(String type, String name, String code,
                        UUID parentId, Map<String, Object> metadata) {

        if (code == null || !CODE_PATTERN.matcher(code).matches()) {
            throw new IllegalArgumentException(
                    "code is required: 1-50 chars of letters, digits or underscore");
        }
        if (parentId == null) {
            throw new IllegalArgumentException(
                    "parentId is required — the single ROOT scope already exists");
        }

        Scope parent = scopeRepository.findById(parentId)
                .orElseThrow(() -> new IllegalArgumentException("Parent scope not found"));

        validateTypeAgainstRegistry(type, parent);

        Scope scope = Scope.builder()
                .type(type)
                .name(name)
                .code(code)
                .parentId(parentId)
                .path(parent.getPath() + "." + code)
                .depth(parent.getDepth() + 1)
                .metadata(metadata != null ? metadata : new HashMap<>())
                .active(true)
                .createdBy("system")
                .build();

        Scope saved = scopeRepository.save(scope);
        cacheService.invalidateScopeCache();

        log.info("Created scope {} ({}) under {}", code, type, parent.getCode());
        return saved;
    }

    /**
     * Managed re-parenting: rebuilds the subtree's closure rows, ltree paths
     * and depths in one transaction. The only legal way to move a scope —
     * direct parent_id updates are blocked by trigger unless this
     * transaction's GUC is set.
     */
    @Transactional
    public Scope move(UUID scopeId, UUID newParentId) {
        Scope moved = scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));
        if (moved.getParentId() == null) {
            throw new IllegalArgumentException("ROOT cannot be moved");
        }
        if (scopeId.equals(newParentId)) {
            throw new IllegalArgumentException("Cannot move a scope under itself");
        }
        Scope newParent = scopeRepository.findById(newParentId)
                .orElseThrow(() -> new IllegalArgumentException("New parent scope not found"));
        if (newParentId.equals(moved.getParentId())) {
            return moved; // no-op
        }
        if (scopeClosureRepository.scopeContains(scopeId, newParentId)) {
            throw new IllegalArgumentException("Cannot move a scope into its own subtree");
        }

        validateTypeAgainstRegistry(moved.getType(), newParent);

        Scope oldParent = scopeRepository.findById(moved.getParentId())
                .orElseThrow(() -> new IllegalStateException("Parent scope missing"));
        int depthDelta = (newParent.getDepth() + 1) - moved.getDepth();

        entityManager.createNativeQuery("SET LOCAL iam.scope_move = 'on'").executeUpdate();

        // Drop links from ancestors outside the subtree to subtree nodes
        entityManager.createNativeQuery("""
                DELETE FROM scope_closure sc
                USING scope_closure sub
                WHERE sub.ancestor_id = :moved AND sub.descendant_id = sc.descendant_id
                  AND sc.ancestor_id NOT IN (
                      SELECT descendant_id FROM scope_closure WHERE ancestor_id = :moved)
                """)
                .setParameter("moved", scopeId)
                .executeUpdate();

        // Link every ancestor of the new parent (incl. itself) to every subtree node
        entityManager.createNativeQuery("""
                INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
                SELECT sup.ancestor_id, sub.descendant_id, sup.depth + sub.depth + 1
                FROM scope_closure sup
                JOIN scope_closure sub ON sub.ancestor_id = :moved
                WHERE sup.descendant_id = :newParent
                """)
                .setParameter("moved", scopeId)
                .setParameter("newParent", newParentId)
                .executeUpdate();

        // Rewrite paths and depths for the whole subtree
        entityManager.createNativeQuery("""
                UPDATE scopes s
                SET path = CAST(:newParentPath AS ltree)
                           || subpath(s.path, nlevel(CAST(:oldParentPath AS ltree))),
                    depth = s.depth + :delta
                FROM scope_closure c
                WHERE c.ancestor_id = :moved AND c.descendant_id = s.id
                """)
                .setParameter("moved", scopeId)
                .setParameter("newParentPath", newParent.getPath())
                .setParameter("oldParentPath", oldParent.getPath())
                .setParameter("delta", depthDelta)
                .executeUpdate();

        entityManager.createNativeQuery(
                        "UPDATE scopes SET parent_id = :newParent WHERE id = :moved")
                .setParameter("newParent", newParentId)
                .setParameter("moved", scopeId)
                .executeUpdate();

        entityManager.clear();
        cacheService.invalidateScopeCache();

        log.info("Moved scope {} under {} (depth delta {})",
                moved.getCode(), newParent.getCode(), depthDelta);
        return scopeRepository.findById(scopeId).orElseThrow();
    }

    @Transactional(readOnly = true)
    public boolean scopeContains(UUID ancestorId, UUID descendantId) {
        return scopeClosureRepository.scopeContains(ancestorId, descendantId);
    }

    private void validateTypeAgainstRegistry(String type, Scope parent) {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("type is required");
        }
        if (scopeTypeRepository.count() == 0) {
            return; // free-form mode
        }

        ScopeType scopeType = scopeTypeRepository.findByName(type)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown scope type '" + type + "' — not in scope_types registry"));

        List<String> allowedParents = scopeType.getAllowedParentTypes();
        boolean parentIsRoot = parent.getParentId() == null;
        if (allowedParents == null || allowedParents.isEmpty()) {
            if (!parentIsRoot) {
                throw new IllegalArgumentException(
                        "Scope type '" + type + "' may only sit directly under ROOT");
            }
        } else if (!allowedParents.contains(parent.getType())) {
            throw new IllegalArgumentException(
                    "Scope type '" + type + "' not allowed under parent type '"
                            + parent.getType() + "'");
        }
    }
}
