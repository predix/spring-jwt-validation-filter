/*******************************************************************************
 * Copyright 2017 General Electric Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.ge.predix.uaa.token.lib;

import static com.ge.predix.uaa.token.lib.Claims.ADDITIONAL_AZ_ATTR;
import static com.ge.predix.uaa.token.lib.Claims.AUD;
import static com.ge.predix.uaa.token.lib.Claims.AUTHORITIES;
import static com.ge.predix.uaa.token.lib.Claims.AZP;
import static com.ge.predix.uaa.token.lib.Claims.CID;
import static com.ge.predix.uaa.token.lib.Claims.CLIENT_ID;
import static com.ge.predix.uaa.token.lib.Claims.EMAIL;
import static com.ge.predix.uaa.token.lib.Claims.EXP;
import static com.ge.predix.uaa.token.lib.Claims.GRANT_TYPE;
import static com.ge.predix.uaa.token.lib.Claims.IAT;
import static com.ge.predix.uaa.token.lib.Claims.ISS;
import static com.ge.predix.uaa.token.lib.Claims.JTI;
import static com.ge.predix.uaa.token.lib.Claims.SUB;
import static com.ge.predix.uaa.token.lib.Claims.USER_ID;
import static com.ge.predix.uaa.token.lib.Claims.USER_NAME;
import static com.ge.predix.uaa.token.lib.Claims.ZONE_ID;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.StringUtils;

public class TestTokenUtil {

    private static final String TOKEN_ISSUER_ID = "http://localhost:8080/uaa/oauth/token";

    private static final String TOKEN_VERIFYING_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\n"
            + "rn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\n"
            + "fYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\n"
            + "LCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\n"
            + "kqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\n"
            + "jfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\n" + "JwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

    private static final String TOKEN_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV\n"
            + "lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT\n"
            + "JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy\n"
            + "VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc\n"
            + "usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W\n"
            + "SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op\n"
            + "zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY\n"
            + "pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw\n"
            + "UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa\n"
            + "Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO\n"
            + "BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2\n"
            + "RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK\n"
            + "/sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z\n"
            + "cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j\n"
            + "UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA\n"
            + "jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/\n"
            + "+YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr\n"
            + "RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4\n"
            + "PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna\n"
            + "cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I\n"
            + "aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4\n"
            + "DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq\n"
            + "b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv\n"
            + "QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI\n"
            + "fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD\n" + "-----END RSA PRIVATE KEY-----\n";

    private final RsaSigner signer;

    public TestTokenUtil() {

        this.signer = new RsaSigner(TOKEN_SIGNING_KEY);
    }

    public String mockAccessToken(final int validitySeconds) {
        return mockAccessToken(TOKEN_ISSUER_ID, System.currentTimeMillis(), validitySeconds);
    }

    public String mockAccessToken(final long issuedAtMillis, final int validitySeconds) {
        return mockAccessToken(TOKEN_ISSUER_ID, issuedAtMillis, validitySeconds);
    }

    public String mockAccessToken(final String issuerId, final long issuedAtMillis, final int validitySeconds) {
        Collection<GrantedAuthority> clientScopes = Arrays
                .asList(new GrantedAuthority[] { new SimpleGrantedAuthority("uaa.resource") });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(new String[] { "openid" }));
        Set<String> resourceIds = new HashSet<>(Arrays.asList(new String[] { "none" }));
        DefaultOAuth2AccessToken openIdToken = createAccessToken(issuerId, "1adc931e-d65f-4357-b90d-dd4131b8749a",
                "marissa", "marissa@test.com", validitySeconds, clientScopes, requestedScopes, "cf", resourceIds,
                "passsword", null, null, null, null, issuedAtMillis, "uaa");
        return openIdToken.getValue();
    }

    public String mockAccessToken(final int validitySeconds, final String zoneUserScope) {
        Collection<GrantedAuthority> clientScopes = Arrays.asList(new GrantedAuthority[] {
                new SimpleGrantedAuthority("uaa.resource"), new SimpleGrantedAuthority(zoneUserScope) });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(new String[] { "openid", zoneUserScope }));
        Set<String> resourceIds = new HashSet<>(Arrays.asList(new String[] { "none" }));
        DefaultOAuth2AccessToken openIdToken = createAccessToken(TOKEN_ISSUER_ID,
                "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa", "marissa@test.com", validitySeconds, clientScopes,
                requestedScopes, "cf", resourceIds, "passsword", null, null, null, null, System.currentTimeMillis(),
                "uaa");
        return openIdToken.getValue();
    }

    private DefaultOAuth2AccessToken createAccessToken(final String issuerId, final String userId,
            final String username, final String userEmail, final int validitySeconds,
            final Collection<GrantedAuthority> clientScopes, final Set<String> requestedScopes, final String clientId,
            final Set<String> resourceIds, final String grantType, final String refreshToken,
            final Map<String, String> additionalAuthorizationAttributes, final Set<String> responseTypes,
            final String revocableHashSignature, final long issuedAtMillis, final String zoneId) {

        String tokenId = UUID.randomUUID().toString();
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenId);
        if (validitySeconds > 0) {
            accessToken.setExpiration(new Date(issuedAtMillis + (validitySeconds * 1000L)));
        }
        accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        if (null == requestedScopes || requestedScopes.size() == 0) {
            // logger.debug("No scopes were granted");
            throw new InvalidTokenException("No scopes were granted");
        }

        accessToken.setScope(requestedScopes);

        Map<String, Object> info = new HashMap<String, Object>();
        info.put(JTI, accessToken.getValue());
        if (null != additionalAuthorizationAttributes) {
            info.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }
        accessToken.setAdditionalInformation(info);

        String content;
        try {
            content = JsonUtils.writeValueAsString(createJWTAccessToken(accessToken, issuerId, userId, username,
                    userEmail, clientScopes, requestedScopes, clientId, resourceIds, grantType, refreshToken,
                    revocableHashSignature, issuedAtMillis, zoneId));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String token = JwtHelper.encode(content, this.signer).getEncoded();

        // This setter copies the value and returns. Don't change.
        accessToken.setValue(token);

        return accessToken;

    }

    private static Map<String, ?> createJWTAccessToken(final OAuth2AccessToken token, final String issuerId,
            final String userId, final String username, final String userEmail,
            final Collection<GrantedAuthority> clientScopes, final Set<String> requestedScopes, final String clientId,
            final Set<String> resourceIds, final String grantType, final String refreshToken,
            final String revocableHashSignature, final long issuedAtMillis, final String zoneId) {

        Map<String, Object> response = new LinkedHashMap<String, Object>();

        response.put(JTI, token.getAdditionalInformation().get(JTI));
        response.putAll(token.getAdditionalInformation());

        response.put(SUB, userId);
        if (null != clientScopes) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
        }

        response.put(OAuth2AccessToken.SCOPE, requestedScopes);
        response.put(CLIENT_ID, clientId);
        response.put(CID, clientId);
        response.put(AZP, clientId); // openId Connect

        if (null != grantType) {
            response.put(GRANT_TYPE, grantType);
        }
        if (!"client_credentials".equals(grantType)) {
            response.put(USER_ID, userId);
            response.put(USER_NAME, username == null ? userId : username);
            if (null != userEmail) {
                response.put(EMAIL, userEmail);
            }
        }

        if (StringUtils.hasText(revocableHashSignature)) {
            response.put(Claims.REVOCATION_SIGNATURE, revocableHashSignature);
        }

        response.put(IAT, issuedAtMillis / 1000);
        if (token.getExpiration() != null) {
            response.put(EXP, token.getExpiration().getTime() / 1000);
        }

        if (issuerId != null) {
            response.put(ISS, issuerId);
            response.put(ZONE_ID, zoneId);
        }

        response.put(AUD, resourceIds);

        return response;
    }

    public static ResponseEntity<Map<String, Object>> mockTokenKeyResponseEntity() {
        Map<String, Object> responseEntityBody = new HashMap<>();
        responseEntityBody.put("alg", "SHA256withRSA");
        responseEntityBody.put("value", TOKEN_VERIFYING_KEY);
        responseEntityBody.put("kty", "RSA");
        responseEntityBody.put("use", "sig");
        responseEntityBody.put("n",
                "ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZ"
                        + "eAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feV"
                        + "P9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tV"
                        + "kkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=");
        responseEntityBody.put("e", "AQAB");
        return new ResponseEntity<Map<String, Object>>(responseEntityBody, HttpStatus.OK);
    }
}
