package io.github.mesubash.iam.shared.dto;

import org.springframework.data.domain.Page;

import java.util.List;

/**
 * Stable pagination envelope. Spring's PageImpl JSON is not a stable contract,
 * so paged endpoints return this flat shape instead.
 */
public record PageResponse<T>(
        List<T> content,
        long totalElements,
        int totalPages,
        int number,
        int size
) {
    public static <T> PageResponse<T> of(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getTotalElements(),
                page.getTotalPages(), page.getNumber(), page.getSize());
    }
}
