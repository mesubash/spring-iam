package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class AuthControllerResetPasswordTest {

    private final AuthService authService = mock(AuthService.class);
    private final AuthController controller = new AuthController(authService, null, null, null, null);

    @Test
    void acceptsJsonBody() {
        controller.resetPassword(null, null, new AuthController.ResetPasswordRequest("tok", "pass1234"));
        verify(authService).resetPassword("tok", "pass1234");
    }

    @Test
    void stillAcceptsQueryParams() {
        controller.resetPassword("tok", "pass1234", null);
        verify(authService).resetPassword("tok", "pass1234");
    }

    @Test
    void rejectsMissingFields() {
        assertThatThrownBy(() -> controller.resetPassword(null, null, null))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> controller.resetPassword(null, null,
                new AuthController.ResetPasswordRequest("tok", " ")))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(authService);
    }
}
