package com.ge.predix.uaa.token.lib;

import static com.ge.predix.uaa.token.lib.Claims.USER_ID;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_ISSUER_ID;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_KEY_RESPONSE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.utils.Base64;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.testng.annotations.Test;

public class FastTokenMockTest {

    private final TestTokenUtil testTokenUtil = new TestTokenUtil();

    @Test
    public void testAuthenticateLoadingCacheExpiry() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        fastTokenServices.setTrustedIssuers(trustedIssuers());
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        fastTokenServices.setRestTemplate(mockRestTemplate());
        fastTokenServices.afterPropertiesSet();
        String accessToken = this.testTokenUtil.mockAccessToken(60);
        //Populate the Cache (Cache computed)
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
        Mockito.verify(fastTokenServices,times(1)).computeSignatureVerifier(TOKEN_ISSUER_ID);
        //Call to make sure that SignatureVerifier is (Cache retrieved)
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
        Mockito.verify(fastTokenServices,times(1)).computeSignatureVerifier(TOKEN_ISSUER_ID);
        //Ensure the Cache entry for issuer times out
        Thread.sleep(1100L);
        //Call that tries to populate the Cache again
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
        //Validate compute call is made when the entry is not available in Cache (Cache expired and computed again)
        Mockito.verify(fastTokenServices,times(2)).computeSignatureVerifier(TOKEN_ISSUER_ID);
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testAuthenticateUnableFetchPublicKey() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        fastTokenServices.setTrustedIssuers(trustedIssuers());
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        fastTokenServices.setRestTemplate(mockRestTemplate());
        fastTokenServices.afterPropertiesSet();
        String accessToken = this.testTokenUtil.mockAccessToken(60);
        when(fastTokenServices.computeSignatureVerifier(TOKEN_ISSUER_ID)).thenReturn(null);
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testAuthenticateWithTamperedToken() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        String accessToken = this.testTokenUtil.mockAccessToken(60);

        // Start tamper ;)
        String[] jwtParts = accessToken.split("\\.");
        String jwtHeader = jwtParts[0];
        String jwtContent = jwtParts[1];
        String jwtSignature = jwtParts[2];

        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<Map<String, Object>> valueTypeRef = new TypeReference<>() {
            // Nothing to declare.
        };
        String decodedClaims = new String(Base64.decodeBase64(jwtContent));
        Map<String, Object> claims = objectMapper.readValue(decodedClaims, valueTypeRef);
        claims.put(USER_ID, "admin");
        String encodedClaims = Base64.encodeBase64String(objectMapper.writeValueAsBytes(claims));
        accessToken = jwtHeader + "." + encodedClaims + "." + jwtSignature;

        // We've tampered the token so this should fail.
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    @Test(expectedExceptions = BadJwtException.class)
    public void testAuthenticateWithExpiredToken() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        fastTokenServices.setTrustedIssuers(trustedIssuers());
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        fastTokenServices.setRestTemplate(mockRestTemplate());
        fastTokenServices.afterPropertiesSet();
        String accessToken = this.testTokenUtil.mockAccessToken(-2);
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    @Test(expectedExceptions = BadJwtException.class)
    public void testAuthenticateWithFutureToken() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        fastTokenServices.setTrustedIssuers(trustedIssuers());
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        fastTokenServices.setRestTemplate(mockRestTemplate());
        fastTokenServices.afterPropertiesSet();
        String accessToken = this.testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, -10, 5);
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    @Test(expectedExceptions = RestClientException.class)
    public void testAuthenticateWithConnectionTimeout() throws Exception {
        FastTokenServices fastTokenServices  = Mockito.spy(new FastTokenServices());
        fastTokenServices.setTrustedIssuers(trustedIssuers());
        fastTokenServices.setIssuerPublicKeyTTLMillis(1000L);
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenThrow(RestClientException.class);
        fastTokenServices.setRestTemplate(restTemplate);
        fastTokenServices.afterPropertiesSet();
        String accessToken = this.testTokenUtil.mockAccessToken(TOKEN_ISSUER_ID, -10, 5);
        fastTokenServices.authenticate(new BearerTokenAuthenticationToken(accessToken));
    }

    private List<String> trustedIssuers() {
        List<String> trustedIssuers = new ArrayList<>();
        trustedIssuers.add(TOKEN_ISSUER_ID);
        return trustedIssuers;
    }

    private RestTemplate mockRestTemplate() {
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        return restTemplate;
    }

}
