package io.github.mesubash.iam.authn.security;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.security.token.SigningKeyService;
import io.github.mesubash.iam.shared.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtTokenProviderTest {

    private static final String KID = "test-kid";
    private static KeyPair keyPair;

    private SigningKeyService signingKeyService;
    private JwtConfig config;
    private JwtTokenProvider provider;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();
    }

    @BeforeEach
    void setUp() {
        signingKeyService = mock(SigningKeyService.class);
        when(signingKeyService.activeKey()).thenReturn(new SigningKeyService.ActiveKey(KID, keyPair.getPrivate()));
        when(signingKeyService.publicKeyFor(anyString()))
                .thenAnswer(inv -> KID.equals(inv.getArgument(0)) ? (RSAPublicKey) keyPair.getPublic() : null);
        config = new JwtConfig();
        config.setExpiration(900_000);
        config.setIssuer("spring-iam");
        provider = new JwtTokenProvider(config, signingKeyService);
    }

    private UserPrincipal principal() {
        Identity identity = Identity.builder().id(UUID.randomUUID()).primaryEmail("t@example.com").build();
        return UserPrincipal.create(identity, null, List.of("Admin"));
    }

    @Test
    void mintsIssuerAndParsesBack() {
        UserPrincipal p = principal();
        UUID sid = UUID.randomUUID();
        Claims claims = provider.parseToken(provider.generateAccessToken(p, sid));
        assertThat(claims.getIssuer()).isEqualTo("spring-iam");
        assertThat(claims.getSubject()).isEqualTo(p.getId().toString());
        assertThat(claims.get("sid")).isEqualTo(sid.toString());
        assertThat(claims.getAudience()).isNullOrEmpty();
    }

    @Test
    void rejectsTokenFromAnotherIssuer() {
        String foreign = Jwts.builder().header().keyId(KID).and()
                .issuer("someone-else").subject("x")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256).compact();
        assertThatThrownBy(() -> provider.parseToken(foreign)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void audienceIsMintedAndEnforcedWhenConfigured() {
        String noAud = provider.generateAccessToken(principal(), UUID.randomUUID());
        config.setAudience("billing");
        String withAud = provider.generateAccessToken(principal(), UUID.randomUUID());

        assertThat(provider.parseToken(withAud).getAudience()).contains("billing");
        assertThatThrownBy(() -> provider.parseToken(noAud)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void rejectsUnknownKid() {
        String token = provider.generateAccessToken(principal(), UUID.randomUUID());
        when(signingKeyService.publicKeyFor(anyString())).thenReturn(null);
        assertThatThrownBy(() -> provider.parseToken(token)).isInstanceOf(InvalidTokenException.class);
    }
}
