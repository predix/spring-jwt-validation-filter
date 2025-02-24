/*******************************************************************************
 * Copyright 2021 General Electric Company
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

import static com.ge.predix.uaa.token.lib.Claims.AUTHORITIES;
import static com.ge.predix.uaa.token.lib.Claims.CID;
import static com.ge.predix.uaa.token.lib.Claims.EMAIL;
import static com.ge.predix.uaa.token.lib.Claims.GRANT_TYPE;
import static com.ge.predix.uaa.token.lib.Claims.REVOCATION_SIGNATURE;
import static com.ge.predix.uaa.token.lib.Claims.SCOPE;
import static com.ge.predix.uaa.token.lib.Claims.USER_ID;
import static com.ge.predix.uaa.token.lib.Claims.USER_NAME;
import static com.ge.predix.uaa.token.lib.Claims.ZONE_ID;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

public class TestTokenUtil {

    public static final String TOKEN_ISSUER_ID = "http://trusted.issuer/oauth/token";

    private static final String TOKEN_SIGNING_KEY = """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDdTg6/Eb/+0iFD
        hNS2elmVYSPEonJ56HQBD3jKCLaRIVMIjF6ppbzDCBgfhYCdaFSGQ2EPAVbZPEzN
        pJrC5O/CxNdx/utMbqVuhcJAG7w2d2n8ic5snyO9mt5iWKXSMdW0IRgYPadgbeJH
        fMvJhxRmf2WJS4QEo9d4BJKY+soQXJW4phvSdncnKGEqdn9FGv7q13c1Yv6tnR0L
        W12nkKABWLqdLum1M5W0c/H8kN8mu+5p8tM4rUVYP6q6zLJrysuby1ExVVsx72Dr
        ZK0+2FAh6zF/ueslRBVcMNcBgxwfQ+9lt//+I1Gihwv2hHZVbx+6n52MHIKP2Ozd
        KmX8jymfAgMBAAECggEAAK4LYDg5vW//0ilHo1ffi+nvJjIpj95QR5XjP8ZPE/Bk
        75Me0f6Zry+zLfBHDjS9Lbxp6+s2d8G2VVtlblEtu2Icwf46fX2e3HwPYLW1GlBm
        REmtbKqrKBtLBkT8yBcxxN/lJw3pbw5nXOOGl2k8KCR0DLvtUpD+ScwZzIaDYGbR
        nPg3wx6AE/hsU69rYX5OymaiWAHwGpgtPb/Rnt86+85sOQhE27qouVh3v32cmYPs
        OuygJisrTOite3wp50ZB5FOqVt/oMiMt+jgCmUAxnnEfjrFB644gNIBiCmfl20Ac
        22/mBO+2+j8M+mFILTAC024cdV6WWi2JZzWdhMu74QKBgQD/LT7TAAJqIzjpDpBk
        TPwJhSsUR48GydCAPKUZr8kw0QKmfhM/eCw2j/Tmg0xYguF7UUfPq4CXR6kP8Bm+
        UyZLsMesCHKOLA9ltQwFwXY7wzsp88LKksj4nt2NuuOZMifRSjhc/2eH0bHv4mjb
        pIeg8Z4CQN2J75JMysdtmySBvQKBgQDeBNY/fjLz1YX6g6N6cbxELZwuZ4k7BwuM
        y6sy+8h3MfBR2PkMkmkgaH2ngAP8uuyTFDBuMn3ihZimc9Z8cJjYLotGYV4MiuhP
        5dUSY8rvHHjuWcN8yKyVKRS3UbibvobJ6V9EsDy+2Gz7vilOpn5dlqYy13qpqpbX
        EfB0d48YiwKBgFKBiJykliNHPDFuuhUUJzHU0vb9pCsnubic4y0I/14/VkIK5aJR
        8sm5hg+6SEceGlXLFBL7etpvGyTCFzDIpcs3X3gqSw/ZAyl5fmemA9qS52BLJqJl
        D4IDq9MVqF1yMBmli8/V7N2nWYcch5bs/cV2GgbUfk0JHx6hOhYgYY9pAoGAXBq9
        lxGPqcBHGKpLw5wzckVJqaaiM660h/BmUXxKqcg53nqYtzJ2Ek/G8RoWjV4ujsWt
        Ycnol3S84zDjJjS/8887UDNMhP+LaLn8LujfY1r4gEkU5EuL7UVhprtsTpA38sOy
        FhjW2oWGkNlO4aYIfmLlB+qEpKZ0dTyn+GkxIAkCgYA/O9YRY2Le7r2yt7hljGdJ
        YUXOzOzmMrrZ+ev7iiXIhtXc7Y38XN5ss6bdnBJENaElyrNMsmi9SKP45lTHfHob
        F9sB4DYtyQi3mmQcSQHTF91iYR0NSH9jqXsCwrK6BgFQDWihdbgU1WAdFR9lfLre
        q6wo7xaqJqwX7dezdhynlA==
        -----END PRIVATE KEY-----""";

    public static final String TOKEN_KEY_RESPONSE = """
        {
        \t"kty": "RSA",
        \t"e": "AQAB",
        \t"use": "sig",
        \t"kid": "PNna8",
        \t"alg": "RS256",
        \t"value": "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3U4OvxG//tIhQ4TUtnpZlWEjxKJyeeh0AQ94ygi2kSFTCIxeqaW8wwgYH4WAnWhUhkNhDwFW2TxMzaSawuTvwsTXcf7rTG6lboXCQBu8Nndp/InObJ8jvZreYlil0jHVtCEYGD2nYG3iR3zLyYcUZn9liUuEBKPXeASSmPrKEFyVuKYb0nZ3JyhhKnZ/RRr+6td3NWL+rZ0dC1tdp5CgAVi6nS7ptTOVtHPx/JDfJrvuafLTOK1FWD+qusyya8rLm8tRMVVbMe9g62StPthQIesxf7nrJUQVXDDXAYMcH0PvZbf//iNRoocL9oR2VW8fup+djByCj9js3Spl/I8pnwIDAQAB-----END PUBLIC KEY-----",
        \t"n": "AN1ODr8Rv_7SIUOE1LZ6WZVhI8SicnnodAEPeMoItpEhUwiMXqmlvMMIGB-FgJ1oVIZDYQ8BVtk8TM2kmsLk78LE13H-60xupW6FwkAbvDZ3afyJzmyfI72a3mJYpdIx1bQhGBg9p2Bt4kd8y8mHFGZ_ZYlLhASj13gEkpj6yhBclbimG9J2dycoYSp2f0Ua_urXdzVi_q2dHQtbXaeQoAFYup0u6bUzlbRz8fyQ3ya77mny0zitRVg_qrrMsmvKy5vLUTFVWzHvYOtkrT7YUCHrMX-56yVEFVww1wGDHB9D72W3__4jUaKHC_aEdlVvH7qfnYwcgo_Y7N0qZfyPKZ8="
        }""";

    public TestTokenUtil() {
    }

    public String mockAccessToken(final int validityMinutes) {
        return mockAccessToken(TOKEN_ISSUER_ID, System.currentTimeMillis(), validityMinutes);
    }

    public String mockAccessToken(final String issuerId, final long issuedAtMinutes, final int validityMinutes) {
        Collection<GrantedAuthority> clientScopes = Arrays
            .asList(new GrantedAuthority[] { new SimpleGrantedAuthority("uaa.resource") });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList("openid", "stuf.write"));
        Set<String> resourceIds = new HashSet<>(List.of("none"));
        return createAccessToken(issuerId, "1adc931e-d65f-4357-b90d-dd4131b8749a",
                                 "marissa", "marissa@test.com", validityMinutes, clientScopes, requestedScopes, "cf",
                                 resourceIds,
                                 "passsword", null, null, issuedAtMinutes, "uaa");
    }

    public Authentication mockAuthentication(final int validityMinutes, final String zoneUserScope) {
        Collection<GrantedAuthority> clientScopes = Arrays.asList(new GrantedAuthority[] {
            new SimpleGrantedAuthority("uaa.resource"), new SimpleGrantedAuthority(zoneUserScope)
        });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList("openid", zoneUserScope));
        Set<String> resourceIds = new HashSet<>(List.of("none"));
        String openIdToken = createAccessToken(TOKEN_ISSUER_ID,
                                               "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa", "marissa@test.com",
                                               validityMinutes, clientScopes,
                                               requestedScopes, "cf", resourceIds, "passsword", null,
                                               null, System.currentTimeMillis(),
                                               "uaa");
        return new BearerTokenAuthenticationToken(openIdToken);
    }

    public String mockAccessToken(final String issuerId, final int validityMinutes, final String zoneUserScope) {
        Collection<GrantedAuthority> clientScopes = Arrays.asList(new GrantedAuthority[] {
            new SimpleGrantedAuthority("uaa.resource"), new SimpleGrantedAuthority(zoneUserScope)
        });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList("openid", zoneUserScope));
        Set<String> resourceIds = new HashSet<>(List.of("none"));
        return createAccessToken(issuerId,
                                 "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa",
                                 "marissa@test.com", validityMinutes, clientScopes,
                                 requestedScopes, "cf", resourceIds, "passsword", null,
                                 null, System.currentTimeMillis(),
                                 "uaa");
    }

    private String createAccessToken(final String issuerId, final String userId,
                                     final String username, final String userEmail, final int validityMinutes,
                                     final Collection<GrantedAuthority> clientScopes, final Set<String> requestedScopes,
                                     final String clientId,
                                     final Set<String> resourceIds, final String grantType,
                                     final Map<String, String> additionalAuthorizationAttributes,
                                     final String revocableHashSignature, final long issuedAtMinutes,
                                     final String zoneId) {
        Instant now = Instant.now();

        try {
            // Create JWT claims
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer(issuerId)
                .issueTime(Date.from(now.minus(issuedAtMinutes, ChronoUnit.MINUTES)))
                .expirationTime(Date.from(now.plus(validityMinutes, ChronoUnit.MINUTES))) // 1 hour expiration
                .claim(SCOPE, requestedScopes)
                .claim(CID, clientId)

                .claim(ZONE_ID, zoneId)
                .claim(EMAIL, userEmail)
                .claim(USER_ID, userId)
                .claim(USER_NAME, username)
                .claim(GRANT_TYPE, grantType)
                .claim(REVOCATION_SIGNATURE, revocableHashSignature)
                .build();
            // Create a new JWS object
            SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claimsSet
            );
            signedJWT.sign(new RSASSASigner(getPrivateKey()));

            // Serialize the token to a string
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey getPrivateKey() {
        String rsaPrivateKey = TOKEN_SIGNING_KEY.replace("-----BEGIN PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replaceAll("\\s", "").replaceAll("\n", "");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
