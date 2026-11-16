package io.github.mesubash.iam.authn.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaChallengeServiceTest {

    @Mock
    private StringRedisTemplate redis;
    @Mock
    private ValueOperations<String, String> ops;

    private final Map<String, String> store = new HashMap<>();
    private MfaChallengeService service;

    @BeforeEach
    void setUp() {
        service = new MfaChallengeService(redis);
        when(redis.opsForValue()).thenReturn(ops);
        // in-memory fake for set/get
        org.mockito.Mockito.doAnswer(inv -> {
            store.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(ops).set(anyString(), anyString(), any(java.time.Duration.class));
        when(ops.get(anyString())).thenAnswer(inv -> store.get(inv.getArgument(0, String.class)));
    }

    @Test
    void challenge_roundtrips_identity() {
        UUID id = UUID.randomUUID();
        String token = service.issueChallenge(id);
        assertThat(service.peekChallenge(token)).contains(id);
    }

    @Test
    void unknown_or_null_token_is_empty() {
        assertThat(service.peekChallenge("nope")).isEmpty();
        assertThat(service.peekChallenge(null)).isEmpty();
    }

    @Test
    void attempts_counter_counts_down_to_zero() {
        when(ops.increment(anyString()))
                .thenReturn(1L, 2L, 3L, 4L, 5L);
        String token = "t";
        assertThat(service.registerFailure(token)).isEqualTo(4);
        assertThat(service.registerFailure(token)).isEqualTo(3);
        assertThat(service.registerFailure(token)).isEqualTo(2);
        assertThat(service.registerFailure(token)).isEqualTo(1);
        assertThat(service.registerFailure(token)).isEqualTo(0);
    }
}
