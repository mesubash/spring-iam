package io.github.mesubash.iam.authn.dto;

import jakarta.validation.constraints.Size;

/** A blank or null name clears the display name. */
public record AdminSetDisplayNameRequest(
        @Size(max = 150, message = "Name must be at most 150 characters") String name) {
}
