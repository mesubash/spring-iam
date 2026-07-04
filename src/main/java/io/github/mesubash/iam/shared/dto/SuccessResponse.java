package io.github.mesubash.iam.shared.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SuccessResponse {
    private String message;

    public static SuccessResponse of(String message) {
        return new SuccessResponse(message);
    }
}
