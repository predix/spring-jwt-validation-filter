/*******************************************************************************
 * Copyright 2016 General Electric Company.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.ge.predix.uaa.token.lib;

import static com.ge.predix.uaa.token.lib.Claims.USER_ID;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.mockito.Mockito;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.testng.annotations.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class FastTokenServiceTest {

    private final TestTokenUtil testTokenUtil = new TestTokenUtil();

    private static final String TOKEN_ISSUER_ID = "http://localhost:8080/uaa/oauth/token";

    private static final String TOKEN_KEY_URL = "https://localhost:8080/uaa/token_key";

    private final FastTokenServices services = new FastTokenServices();

    private final Map<String, Object> body = new HashMap<>();

    public FastTokenServiceTest() throws Exception {

        this.body.put(Claims.CLIENT_ID, "remote");
        this.body.put(Claims.USER_NAME, "olds");
        this.body.put(Claims.EMAIL, "olds@vmware.com");
        this.body.put(Claims.ISS, TOKEN_ISSUER_ID);
        this.body.put(Claims.USER_ID, "HDGFJSHGDF");

        ParameterizedTypeReference<Map<String, Object>> typeRef =
                new ParameterizedTypeReference<Map<String, Object>>() {
            // Nothing to add.
        };

        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        Mockito.when(restTemplate.exchange(TOKEN_KEY_URL, HttpMethod.GET, null, typeRef))
                .thenReturn(TestTokenUtil.mockTokenKeyResponseEntity());
        this.services.setRestTemplate(restTemplate);

        List<String> trustedIssuers = new ArrayList<>();
        trustedIssuers.add(TOKEN_ISSUER_ID);
        this.services.setTrustedIssuers(trustedIssuers);
    }

    @Test
    public void testLoadAuthentication() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken(60);
        OAuth2Authentication result = this.services.loadAuthentication(accessToken);
        assertNotNull(result);
        assertEquals("cf", result.getOAuth2Request().getClientId());
        assertEquals("marissa", result.getUserAuthentication().getName());
        assertEquals("1adc931e-d65f-4357-b90d-dd4131b8749a",
                ((RemoteUserAuthentication) result.getUserAuthentication()).getId());
        assertNotNull(result.getOAuth2Request().getRequestParameters());
        assertNull(result.getOAuth2Request().getRequestParameters().get(Claims.ISS));
    }

    /**
     * Tests that an token from the another other issuer id.
     */
    public void testLoadAuthenticationWithOtherIssuerId() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken("http://testzone1.localhost:8080/uaa/oauth/token",
                System.currentTimeMillis() - 240000, 60);
        OAuth2Authentication result = this.services.loadAuthentication(accessToken);
        assertNotNull(result);
        assertEquals("cf", result.getOAuth2Request().getClientId());
        assertEquals("marissa", result.getUserAuthentication().getName());
        assertEquals("1adc931e-d65f-4357-b90d-dd4131b8749a",
                ((RemoteUserAuthentication) result.getUserAuthentication()).getId());
        assertNotNull(result.getOAuth2Request().getRequestParameters());

    }

    /**
     * Tests that an token from the an untrusted issuer id throws an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationWithUnstrustedIssuerId() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken("http://testzone1localhost:8080/uaa/oauth/token",
                System.currentTimeMillis() - 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that an expired token issues an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationWithExpiredToken() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken(System.currentTimeMillis() - 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that an token that is valid for future use issues an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationWithFutureToken() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken(System.currentTimeMillis() + 240000, 60);
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that null token issues an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationWithNullTokenString() throws Exception {
        this.services.loadAuthentication("null");
    }

    /**
     * Tests that a tampered token issues an InvalidTokenException.
     */
    @Test(expectedExceptions = InvalidSignatureException.class)
    public void testLoadAuthenticationWithTamperedToken() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken(60);

        // Start tamper ;)
        String[] jwtParts = accessToken.split("\\.");
        String jwtHeader = jwtParts[0];
        String jwtContent = jwtParts[1];
        String jwtSignature = jwtParts[2];

        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<Map<String, Object>> valueTypeRef = new TypeReference<Map<String, Object>>() {
            // Nothing to declare.
        };
        String decodedClaims = new String(Base64.decodeBase64(jwtContent));
        Map<String, Object> claims = objectMapper.readValue(decodedClaims, valueTypeRef);
        claims.put(USER_ID, "admin");
        String encodedClaims = Base64.encodeBase64String(objectMapper.writeValueAsBytes(claims));
        accessToken = jwtHeader + "." + encodedClaims + "." + jwtSignature;

        // We've tampered the token so this should fail.
        this.services.loadAuthentication(accessToken);
    }

    /**
     * Tests that connection error while retrieving token key issues RestClientException.
     */
    @SuppressWarnings("unchecked")
    @Test(expectedExceptions = RestClientException.class)
    public void testLoadAuthenticationWithConnectionTimeout() throws Exception {
        String accessToken = this.testTokenUtil.mockAccessToken(60);

        FastTokenServices services = new FastTokenServices();
        ParameterizedTypeReference<Map<String, Object>> typeRef =
                new ParameterizedTypeReference<Map<String, Object>>() {
            // Nothing to add.
        };
        RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
        Mockito.when(restTemplate.exchange(TOKEN_KEY_URL, HttpMethod.GET, null, typeRef))
                .thenThrow(RestClientException.class);
        services.setRestTemplate(restTemplate);

        services.loadAuthentication(accessToken);
    }

    /**
     * This tests that we can extract the issuer from the token claims.
     */
    @Test
    public void testGetIssuerFromClaims() {
        String accessToken = this.testTokenUtil.mockAccessToken(60);

        assertEquals(TOKEN_ISSUER_ID, this.services.getIssuerFromClaims(this.services.getTokenClaims(accessToken)));

    }

    /**
     * This tests that we can derive the token_key endpoint from the issuer id. E.g.
     * http://localhost:8080/uaa/oauth/token -> https://localhost:8080/uaa/token_key
     */
    @Test
    public void testGetTokenKeyURL() {
        assertEquals("https://localhost:8080/uaa/token_key", this.services.getTokenKeyURL(TOKEN_ISSUER_ID));

        assertEquals("https://sample.com/token_key", this.services.getTokenKeyURL("https://sample.com/oauth/token"));
    }

}
