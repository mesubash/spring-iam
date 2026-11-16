package io.github.mesubash.iam.config;

import io.github.mesubash.iam.authz.entity.AdminAuditLog;
import io.github.mesubash.iam.authz.service.AdminAuditService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AdminAuditFilterTest {

    private final AdminAuditService service = mock(AdminAuditService.class);
    private final AdminAuditFilter filter = new AdminAuditFilter(service);

    private void call(String method, String path, int status) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(status);
        filter.doFilter(request, response, new MockFilterChain());
    }

    @Test
    void recordsSuccessfulAdminMutation() throws Exception {
        call("DELETE", "/api/v1/roles/42", 204);

        ArgumentCaptor<AdminAuditLog> entry = ArgumentCaptor.forClass(AdminAuditLog.class);
        verify(service).record(entry.capture());
        assertEquals("DELETE", entry.getValue().getMethod());
        assertEquals("/api/v1/roles/42", entry.getValue().getPath());
        assertEquals(204, entry.getValue().getStatus());
    }

    @Test
    void skipsReadsRejectionsDecisionCallsAndOwnAccountFlows() throws Exception {
        call("GET", "/api/v1/roles", 200);
        call("POST", "/api/v1/roles", 403);
        call("POST", "/api/v1/authorize", 200);
        call("POST", "/api/v1/authorize/batch", 200);
        call("POST", "/api/v1/token/introspect", 200);
        call("POST", "/api/auth/mfa/setup", 200);
        call("POST", "/api/auth/login", 200);

        verify(service, never()).record(any());
    }
}
