package com.ge.predix.uaa.token.lib;

import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_ISSUER_ID;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_KEY_RESPONSE;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.SignedJWT;
import org.mockito.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.*;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.testng.annotations.*;

public class FastTokenServicesTest {

    @Mock
    private RestOperations mockRestTemplate;

    private final TestTokenUtil testTokenUtil = new TestTokenUtil();

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = null;

    @InjectMocks
    private FastTokenServices fastTokenServices;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        fastTokenServices = new FastTokenServices();
        fastTokenServices.setRestTemplate(mockRestTemplate);
        fastTokenServices.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        fastTokenServices.afterPropertiesSet();
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtAuthenticationConverter = new JwtAuthenticationConverter();
        ((JwtAuthenticationConverter)jwtAuthenticationConverter).setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    }

    @Test
    public void authenticate_ValidToken_ReturnsAuthentication() throws Exception {
        String token =
            testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC)
                                                                     .toEpochMilli(), 60);
        Map<String, Object> claimMap = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        Map<String, Object> tokenMap = new HashMap<>(claimMap);
        tokenMap.put(Claims.IAT, LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC));
        tokenMap.put(Claims.EXP, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC));
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "RS256").claims((c) -> c.putAll(tokenMap)).build();
        JwtAuthenticationToken authenticationToken =
            (JwtAuthenticationToken) jwtAuthenticationConverter.convert(jwt);
        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        Authentication result = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));

        assertNotNull(result);
        assertNotNull(authenticationToken);
        assertNotNull(result.getPrincipal());
        assertNotNull(result.getCredentials());
        assertEquals(result.getAuthorities(), authenticationToken.getAuthorities());
        assertEquals(result.getAuthorities().size(), authenticationToken.getAuthorities().size());
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void authenticate_InvalidToken_ThrowsException() {
        String accessToken = "invalidAccessToken";
        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenThrow(new RuntimeException("Error"));
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    @Test
    public void verifyIssuer_TrustedIssuer_DoesNotThrowException() {
        fastTokenServices.setTrustedIssuers(List.of("http://trusted.issuer"));
        fastTokenServices.verifyIssuer("http://trusted.issuer");
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void verifyIssuer_UntrustedIssuer_ThrowsException() {
        fastTokenServices.setTrustedIssuers(List.of("http://trusted.issuer"));
        fastTokenServices.verifyIssuer("http://untrusted.issuer");
    }


    @Test
    public void testLoadAuthenticationForUpdatedIssuerTokenSigningKeyPositive() throws Exception {
        FastTokenServices fastTokenServices  = new FastTokenServices();
        fastTokenServices.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        fastTokenServices.setIssuerPublicKeyTTLMillis(3000L);
        fastTokenServices.afterPropertiesSet();
        fastTokenServices.setRestTemplate(mockRestTemplate());

        String accessToken = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC)
                                                                                         .toEpochMilli(), 60);

        var result = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
        assertNotNull(result);
        fastTokenServices.setRestTemplate(mockRestTemplate());
        //Ensure the TokenKey for issuer times out
        Thread.sleep(3100L);
        accessToken = this.testTokenUtil.mockAccessToken(60);
        result = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
        assertNotNull(result);
    }

    /**
     * Tests that an token from the an untrusted issuer id throws an InvalidTokenException.
     */
    @Test(
        expectedExceptions = InvalidBearerTokenException.class,
        expectedExceptionsMessageRegExp = ".*is not trusted because it is not in the configured list of trusted "
                                          + "issuers.")
    public void testLoadAuthenticationWithUnstrustedIssuerId() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken("http://testzone1localhost:8080/uaa/oauth/token",
                                                                System.currentTimeMillis(), 60);
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    /**
     * Tests that null token issues an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testLoadAuthenticationWithNullTokenString() throws Exception {
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken("null"));
    }

    /**
     * Tests that empty token issues an InvalidTokenException.
     */
    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "token cannot be empty")
    public void testLoadAuthenticationWithEmptyToken() {
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(""));
    }

    @Test(expectedExceptions=InvalidBearerTokenException.class)
    public void testWithNoTrustedIssuers() {
        FastTokenServices  tokenService = new FastTokenServices();

        tokenService.authenticate(new BearerTokenAuthenticationToken(this.testTokenUtil.mockAccessToken(60)));
    }

    /**
     * This tests that we can extract the issuer from the token claims.
     */
    @Test
    public void testGetIssuerFromClaims() throws ParseException {
        String accessToken = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC)
                                                                                             .toEpochMilli(), 60);

        assertEquals(fastTokenServices.getIssuerFromClaims(fastTokenServices.getTokenClaims(SignedJWT.parse(accessToken))),
                     TOKEN_ISSUER_ID);

    }

    /**
     * This tests that we can derive the token_key endpoint from the issuer id. E.g.
     * http://localhost:8080/uaa/oauth/token -> https://localhost:8080/uaa/token_key
     */
    @Test
    public void testGetTokenKeyURL() {
        assertEquals(fastTokenServices.getTokenKeyURL(TOKEN_ISSUER_ID), "https://trusted.issuer/token_key");

        assertEquals(fastTokenServices.getTokenKeyURL("https://sample.com/oauth/token"),
                     "https://sample.com/token_key");
    }

    private RestTemplate mockRestTemplate() {
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        return restTemplate;
    }
}