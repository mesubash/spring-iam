package io.github.mesubash.iam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Swagger UI and the spec are public and live entirely under /docs. */
@SpringBootTest
@AutoConfigureMockMvc
class ApiDocsIntegrationTest {

    @Autowired private MockMvc mvc;

    @Test
    void docsAreServedUnderDocsWithoutCredentials() throws Exception {
        mvc.perform(get("/docs")).andExpect(redirectedUrl("/docs/swagger-ui/index.html"));
        mvc.perform(get("/docs/swagger-ui/index.html")).andExpect(status().isOk());
        mvc.perform(get("/docs/openapi.json")).andExpect(status().isOk());
    }
}
