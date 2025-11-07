package com.ge.predix.uaa.token.lib;

import static com.ge.predix.uaa.token.lib.Claims.AUTHORITIES;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_ISSUER_ID;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_KEY_RESPONSE;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.SignedJWT;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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

    @Test
    public void authenticate_ValidToken_Valid_ResourceId() throws Exception {
        String token =
            testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC)
                                                                        .toEpochMilli(), 60);
        Map<String, Object> claimMap = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        Map<String, Object> tokenMap = new HashMap<>(claimMap);
        tokenMap.put(Claims.IAT, LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC));
        tokenMap.put(Claims.EXP, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC));
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "RS256").claims((c) -> c.putAll(tokenMap)).build();
        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        fastTokenServices.setExpectedResourceId("test.resource");
        fastTokenServices.setResourceIdClaimName(AUTHORITIES);
        Authentication result = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
        assertNotNull(result);
    }

    @Test(expectedExceptions = OAuth2AuthenticationException.class)
    public void authenticate_ValidToken_Invalid_ResourceId() throws Exception {
        String token =
            testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC)
                                                                        .toEpochMilli(), 60);
        Map<String, Object> claimMap = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        Map<String, Object> tokenMap = new HashMap<>(claimMap);
        tokenMap.put(Claims.IAT, LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC));
        tokenMap.put(Claims.EXP, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC));
        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        fastTokenServices.setExpectedResourceId("test.not.resource");
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
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

    @Test
    public void testDefaultConstructor() {
        FastTokenServices service = new FastTokenServices();
        assertNotNull(service);
    }

    @Test
    public void testConstructorWithTTL() {
        FastTokenServices service = new FastTokenServices(10000L);
        assertNotNull(service);
    }

    @Test
    public void testConstructorWithMaxTTL() {
        FastTokenServices service = new FastTokenServices(Long.MAX_VALUE);
        assertNotNull(service);
    }

    @Test
    public void testConstructorWithZeroTTL() {
        FastTokenServices service = new FastTokenServices(0L);
        assertNotNull(service);
    }

    @Test
    public void testSetUseHttps() {
        fastTokenServices.setUseHttps(false);
        assertEquals(fastTokenServices.getTokenKeyURL("http://localhost:8080/uaa/oauth/token"),
                    "http://localhost:8080/uaa/token_key");
    }

    @Test
    public void testSetUseHttpsTrue() {
        fastTokenServices.setUseHttps(true);
        assertEquals(fastTokenServices.getTokenKeyURL("http://localhost:8080/uaa/oauth/token"),
                    "https://localhost:8080/uaa/token_key");
    }

    @Test
    public void testSetMaxAcceptableClockSkewSeconds() {
        fastTokenServices.setMaxAcceptableClockSkewSeconds(120);
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testSetTokenKeyRequestTimeout() {
        fastTokenServices.setTokenKeyRequestTimeout(5);
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testSetIssuerPublicKeyTTLMillis() {
        fastTokenServices.setIssuerPublicKeyTTLMillis(5000L);
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testSetResourceIdClaimName() {
        fastTokenServices.setResourceIdClaimName("client_id");
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testSetJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        fastTokenServices.setJwtAuthenticationConverter(converter);
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testSupports() {
        assertEquals(fastTokenServices.supports(BearerTokenAuthenticationToken.class), true);
    }

    @Test
    public void testSupportsOtherClass() {
        assertEquals(fastTokenServices.supports(String.class), false);
    }

    @Test
    public void testAfterPropertiesSet() throws Exception {
        FastTokenServices service = new FastTokenServices();
        service.setIssuerPublicKeyTTLMillis(1000L);
        service.afterPropertiesSet();
        assertNotNull(service);
    }

    @Test
    public void testAfterPropertiesSetMultipleTimes() throws Exception {
        FastTokenServices service = new FastTokenServices();
        service.afterPropertiesSet();
        service.afterPropertiesSet();
        service.afterPropertiesSet();
        assertNotNull(service);
    }

    @Test
    public void testGetTokenKeyURLWithNullIssuer() {
        String result = fastTokenServices.getTokenKeyURL(null);
        assertEquals(result, null);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testGetTokenKeyURLWithInvalidIssuer() {
        fastTokenServices.getTokenKeyURL("invalid-issuer");
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testGetTokenKeyURLWithoutOAuthToken() {
        fastTokenServices.getTokenKeyURL("http://localhost:8080/uaa");
    }

    @Test
    public void testGetTokenKeyURLWithHttps() {
        String result = fastTokenServices.getTokenKeyURL("https://example.com/uaa/oauth/token");
        assertEquals(result, "https://example.com/uaa/token_key");
    }

    @Test
    public void testGetTokenKeyURLWithHttp() {
        fastTokenServices.setUseHttps(false);
        String result = fastTokenServices.getTokenKeyURL("http://example.com/uaa/oauth/token");
        assertEquals(result, "http://example.com/uaa/token_key");
    }

    @Test
    public void testGetTokenClaims() throws ParseException {
        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(1).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);
        SignedJWT signedJWT = SignedJWT.parse(token);
        Map<String, Object> claims = fastTokenServices.getTokenClaims(signedJWT);
        assertNotNull(claims);
        assertEquals(claims.get(Claims.ISS), TOKEN_ISSUER_ID);
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class,
          expectedExceptionsMessageRegExp = ".*is not trusted.*")
    public void testVerifyIssuerWithMultipleTrustedIssuers() {
        fastTokenServices.setTrustedIssuers(List.of("http://issuer1", "http://issuer2", "http://issuer3"));
        fastTokenServices.verifyIssuer("http://untrusted");
    }

    @Test
    public void testVerifyIssuerWithMultipleTrustedIssuersValid() {
        fastTokenServices.setTrustedIssuers(List.of("http://issuer1", "http://issuer2", "http://issuer3"));
        fastTokenServices.verifyIssuer("http://issuer2");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testVerifyIssuerWithEmptyTrustedIssuers() {
        fastTokenServices.setTrustedIssuers(List.of());
        fastTokenServices.verifyIssuer("http://anyissuer");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testVerifyIssuerWithNullTrustedIssuers() {
        fastTokenServices.setTrustedIssuers(null);
        fastTokenServices.verifyIssuer("http://anyissuer");
    }

    @Test
    public void testAuthenticateWithValidResourceId() throws Exception {
        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);
        Map<String, Object> claimMap = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        Map<String, Object> tokenMap = new HashMap<>(claimMap);
        tokenMap.put(Claims.IAT, LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC));
        tokenMap.put(Claims.EXP, LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC));

        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));

        fastTokenServices.setExpectedResourceId(null);
        Authentication result = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
        assertNotNull(result);
    }

    @Test(expectedExceptions = OAuth2AuthenticationException.class)
    public void testAuthenticateWithNullAudienceList() throws Exception {
        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);

        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));

        fastTokenServices.setExpectedResourceId("some.resource");
        fastTokenServices.setResourceIdClaimName("nonexistent_claim");
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
    }

    @Test
    public void testGetTokenKeyWithRestTemplateInitialization() {
        FastTokenServices service = new FastTokenServices();
        service.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        service.setTokenKeyRequestTimeout(10);

        RestTemplate mockRest = mockRestTemplate();
        service.setRestTemplate(mockRest);

        String tokenKey = service.getTokenKey(TOKEN_ISSUER_ID);
        assertNotNull(tokenKey);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testGetTokenKeyWithException() {
        FastTokenServices service = new FastTokenServices();
        RestTemplate mockRest = Mockito.mock(RestTemplate.class);
        when(mockRest.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenThrow(new RuntimeException("Connection error"));
        service.setRestTemplate(mockRest);

        service.getTokenKey("http://example.com/oauth/token");
    }

    @Test
    public void testSetTrustedIssuersWithSingleIssuer() {
        fastTokenServices.setTrustedIssuers(List.of("http://single.issuer"));
        fastTokenServices.verifyIssuer("http://single.issuer");
    }

    @Test
    public void testSetTrustedIssuersWithMultipleIssuers() {
        List<String> issuers = List.of("http://issuer1", "http://issuer2", "http://issuer3", "http://issuer4");
        fastTokenServices.setTrustedIssuers(issuers);
        fastTokenServices.verifyIssuer("http://issuer1");
        fastTokenServices.verifyIssuer("http://issuer4");
    }

    @Test
    public void testConstructorInitializesJwtAuthenticationConverter() throws Exception {
        FastTokenServices service = new FastTokenServices();
        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);

        service.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        service.setRestTemplate(mockRestTemplate());
        service.afterPropertiesSet();

        Authentication result = service.authenticate(new BearerTokenAuthenticationToken(token));
        assertNotNull(result);
    }

    @Test
    public void testCacheExpirationAndReload() throws Exception {
        FastTokenServices service = new FastTokenServices(); // Default constructor initializes converter
        service.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        service.setRestTemplate(mockRestTemplate());
        service.setIssuerPublicKeyTTLMillis(100L); // 100ms TTL
        service.afterPropertiesSet();

        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);

        Authentication result1 = service.authenticate(new BearerTokenAuthenticationToken(token));
        assertNotNull(result1);

        Thread.sleep(150); // Wait for cache to expire

        Authentication result2 = service.authenticate(new BearerTokenAuthenticationToken(token));
        assertNotNull(result2);
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testAuthenticateWithMalformedToken() {
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken("malformed.jwt.token"));
    }

    @Test
    public void testMultipleAuthenticationCalls() throws Exception {
        String token = testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID,
            LocalDateTime.now().plusDays(3).toInstant(ZoneOffset.UTC).toEpochMilli(), 60);

        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));

        Authentication result1 = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
        Authentication result2 = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
        Authentication result3 = fastTokenServices.authenticate(new BearerTokenAuthenticationToken(token));

        assertNotNull(result1);
        assertNotNull(result2);
        assertNotNull(result3);
    }

    @Test
    public void testSetIssuerPublicKeyTTLMillisWithDifferentValues() {
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        fastTokenServices.setIssuerPublicKeyTTLMillis(Long.MAX_VALUE);
        fastTokenServices.setIssuerPublicKeyTTLMillis(0L);
        assertNotNull(fastTokenServices);
    }

    @Test
    public void testGetTokenKeyURLWithDifferentPaths() {
        String url1 = fastTokenServices.getTokenKeyURL("http://example.com/path1/oauth/token");
        assertEquals(url1, "https://example.com/path1/token_key");

        String url2 = fastTokenServices.getTokenKeyURL("http://example.com/path1/path2/oauth/token");
        assertEquals(url2, "https://example.com/path1/path2/token_key");
    }
}