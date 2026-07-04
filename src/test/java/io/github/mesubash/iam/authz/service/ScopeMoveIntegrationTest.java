package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Scope;
import io.github.mesubash.iam.authz.repository.ScopeClosureRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the managed scope move against a real Postgres
 * (closure rebuild, ltree path rewrite, GUC-gated trigger).
 * Requires docker compose postgres + redis, like the context test.
 */
@SpringBootTest(properties = {
        "spring.security.oauth2.client.registration.google.client-id=test-client",
        "spring.security.oauth2.client.registration.google.client-secret=test-secret"
})
class ScopeMoveIntegrationTest {

    @Autowired private ScopeService scopeService;
    @Autowired private ScopeClosureRepository closureRepository;

    @Test
    void moveRebuildsClosurePathsAndDepths() {
        String run = Integer.toHexString((int) (System.nanoTime() & 0xffffff));
        UUID root = scopeService.getRoot().getId();

        Scope orgA = scopeService.create("ORG", "Org A", "MVA_" + run, root, null);
        Scope orgB = scopeService.create("ORG", "Org B", "MVB_" + run, root, null);
        Scope team = scopeService.create("TEAM", "Team", "MVT_" + run, orgA.getId(), null);
        Scope sub  = scopeService.create("UNIT", "Unit", "MVU_" + run, team.getId(), null);

        Scope movedTeam = scopeService.move(team.getId(), orgB.getId());

        // parent, path, depth rewritten for the whole subtree
        assertEquals(orgB.getId(), movedTeam.getParentId());
        assertEquals(orgB.getPath() + ".MVT_" + run, movedTeam.getPath());
        assertEquals(orgB.getDepth() + 1, movedTeam.getDepth());

        Scope movedSub = scopeService.getById(sub.getId()).orElseThrow();
        assertEquals(orgB.getPath() + ".MVT_" + run + ".MVU_" + run, movedSub.getPath());
        assertEquals(orgB.getDepth() + 2, movedSub.getDepth());

        // closure: new ancestor chain in, old one out, root keeps everything
        assertTrue(closureRepository.scopeContains(orgB.getId(), sub.getId()));
        assertFalse(closureRepository.scopeContains(orgA.getId(), sub.getId()));
        assertTrue(closureRepository.scopeContains(root, sub.getId()));

        // moving into own subtree is rejected
        assertThrows(IllegalArgumentException.class,
                () -> scopeService.move(orgB.getId(), sub.getId()));
    }
}
