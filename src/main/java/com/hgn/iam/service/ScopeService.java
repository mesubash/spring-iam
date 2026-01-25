package com.hgn.iam.service;
import com.hgn.iam.entity.Scope;
import com.hgn.iam.repository.ScopeClosureRepository;
import com.hgn.iam.repository.ScopeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScopeService {

    private final ScopeRepository scopeRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final CacheService cacheService;

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
    public Optional<Scope> getByCode(String code) {
        return scopeRepository.findByCode(code);
    }

    @Transactional(readOnly = true)
    public List<Scope> getDescendants(UUID scopeId) {
        Scope scope = scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));

        return scopeRepository.findDescendants(scope.getPath());
    }

    @Transactional
    public Scope create(String type, String name, String code,
                        UUID parentId, Map<String, Object> metadata) {

        // Validate type
        if (!Arrays.asList("GLOBAL", "COUNTRY", "REGION", "ORG", "DEPT", "TEAM", "PROJECT")
                .contains(type)) {
            throw new IllegalArgumentException("Invalid scope type: " + type);
        }

        // Calculate depth and path
        int depth;
        String path;

        if ("GLOBAL".equals(type)) {
            if (parentId != null) {
                throw new IllegalArgumentException("GLOBAL scope cannot have parent");
            }
            depth = 0;
            path = "GLOBAL";
        } else {
            if (parentId == null) {
                throw new IllegalArgumentException("Non-GLOBAL scope must have parent");
            }

            Scope parent = scopeRepository.findById(parentId)
                    .orElseThrow(() -> new IllegalArgumentException("Parent scope not found"));

            depth = parent.getDepth() + 1;
            path = parent.getPath() + "." + name.toUpperCase().replace(" ", "_");
        }

        Scope scope = Scope.builder()
                .type(type)
                .name(name)
                .code(code)
                .parentId(parentId)
                .path(path)
                .depth(depth)
                .metadata(metadata != null ? metadata : new HashMap<>())
                .active(true)
                .createdBy("system")
                .build();

        Scope saved = scopeRepository.save(scope);

        // Closure table will be auto-populated by trigger
        // But we need to invalidate cache
        cacheService.invalidateScopeCache();

        log.info("Created scope: {} ({})", name, type);
        return saved;
    }

    @Transactional(readOnly = true)
    public boolean scopeContains(UUID ancestorId, UUID descendantId) {
        return scopeClosureRepository.scopeContains(ancestorId, descendantId);
    }
}

