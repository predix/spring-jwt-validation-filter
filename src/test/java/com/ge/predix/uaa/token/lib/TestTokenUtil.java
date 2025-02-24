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

import static com.ge.predix.uaa.token.lib.Claims.ADDITIONAL_AZ_ATTR;
import static com.ge.predix.uaa.token.lib.Claims.AUD;
import static com.ge.predix.uaa.token.lib.Claims.AUTHORITIES;
import static com.ge.predix.uaa.token.lib.Claims.AZP;
import static com.ge.predix.uaa.token.lib.Claims.CID;
import static com.ge.predix.uaa.token.lib.Claims.CLIENT_ID;
import static com.ge.predix.uaa.token.lib.Claims.EMAIL;
import static com.ge.predix.uaa.token.lib.Claims.GRANT_TYPE;
import static com.ge.predix.uaa.token.lib.Claims.REVOCATION_SIGNATURE;
import static com.ge.predix.uaa.token.lib.Claims.SCOPE;
import static com.ge.predix.uaa.token.lib.Claims.USER_ID;
import static com.ge.predix.uaa.token.lib.Claims.USER_NAME;
import static com.ge.predix.uaa.token.lib.Claims.ZONE_ID;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.shaded.gson.Gson;
import com.okta.jwt.JwtVerifiers;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

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

    private static final String TOKEN_SIGNING_KEY = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV
        lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT
        JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy
        VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc
        usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W
        SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op
        zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY
        pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw
        UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa
        Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO
        BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2
        RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK
        /sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z
        cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j
        UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA
        jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/
        +YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr
        RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4
        PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna
        cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I
        aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4
        DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq
        b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv
        QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI
        fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD
        -----END RSA PRIVATE KEY-----
        """;

    private static final String UPDATED_TOKEN_VERIFYING_KEY = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qEFBIQNuVVrF9UOy9AP
        7tfdCL19TmjKw16gXHfmSEJMcEzkmM4/wZwStgtX8KFyhnzu3ZjQ9Mbd58Ddht+K
        1Zz32UN1V/vXT7TwocWWPUUNXbEn3Tm6h7MCxbDyoGeXMQdFNq/w3bdHm/L0SOJC
        UjLnOMb0n1PTtq9hNNIT2RTLze/DKabdKaq+oqTKGl1tqDZ8OKQs6PrgChcehuWB
        j+ZXaIaQmLeRWboyS1/H7u7iN3vPpGMqt+/PK1jC87NPtTlq8EHMW8MyOmTUsuWE
        wWMr1bNcmI/snxpbwO9CeE3PwbT1CzA+Ky0zGa++bBcaT3tPMoOef3XS1YCRXzME
        KQIDAQAB
        -----END PUBLIC KEY-----""";

    private static final String UPDATED_TOKEN_SIGNING_KEY = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA1qEFBIQNuVVrF9UOy9AP7tfdCL19TmjKw16gXHfmSEJMcEzk
        mM4/wZwStgtX8KFyhnzu3ZjQ9Mbd58Ddht+K1Zz32UN1V/vXT7TwocWWPUUNXbEn
        3Tm6h7MCxbDyoGeXMQdFNq/w3bdHm/L0SOJCUjLnOMb0n1PTtq9hNNIT2RTLze/D
        KabdKaq+oqTKGl1tqDZ8OKQs6PrgChcehuWBj+ZXaIaQmLeRWboyS1/H7u7iN3vP
        pGMqt+/PK1jC87NPtTlq8EHMW8MyOmTUsuWEwWMr1bNcmI/snxpbwO9CeE3PwbT1
        CzA+Ky0zGa++bBcaT3tPMoOef3XS1YCRXzMEKQIDAQABAoIBAQCJCutfRMpWinoF
        D5+Q99sUkHSr/gIirLq7IJKYOF6ryNlx40cbYqZHA1bXMksGdK/hu6fxin/xq4FJ
        V1abpeTKHJ4M9gvZEA8c79WuFbGmkY7FQjbIBPJbbyvX+vIRBdP+FDxXfOP5TevF
        Yc4lM4NRZPtKv462pRnLzhPtXC4cLwXF1SwkTqU5xbU4T+TWf+CdJPaGW/dI3Lon
        cW6Sor9X80OkATWvZYS/38Hp7eV1962wkfCBz1MPwWBjS/bXJOAWn42kAGRdcL20
        K4P8hTVWNp4ZolO6dNGELtnDM5+0g+LDVNIMWPwqQlSWAvhqx39dCL8RV8jP2FGp
        PPyiWZ/ZAoGBAO7bC+T1D/gDIgAIOM9WQhdF4wMfRFmc7JFOdC2BVJeQ+2RvL8s2
        0KkSeUGN0pYSQI7SNyvrBv8aR2zIkwX5aY/Ck1AVZR+QzZE1QQ9d8kgle5UtQu/9
        /xok+qVGvNcFLo9Nr0sheu04CGYxkkqmvWgxUdZw3LAjX7ZXRSeUWzULAoGBAOYI
        z1+7Xn45a3i2/ynk58VaNFLqsYj/wZkWCKEZn7st2UvIVMpxs+KUk/I8LR1IdIDv
        GfsGVWYeXu9IrBq0sfmg2HbE/0x6LM2pSBWYbtbKQJxlEZqwgzd2HuSzvlZncJjC
        rGYDCpTGXyIiz4jzqWI3wfXJ8UKEQqODROJZ6MQbAoGAUtHY+faPJuvPKjuvlxTN
        rcwpvrdkt73VuTx+xBiIAFXhFR4IcGn9R+KD8NsAHdEOWXdCchP4RRQTmACkGfo1
        RAevlKEWgy9uV98jQ/TLQYDdrQgYoaZsgeA4mH5ClDvTvRSup1pgiUhYgTbHBuNx
        4WLYgYZ4vwpE8bCo5eRnC6kCgYEAgWKnMZN0HM8zMdzMPMYxzwFjuNelMAea3v5T
        sDl3bJLnTAbMGmpF4cXsSS2runLMhND37ger9RpUD4bytrq3+E6OMo+vgVae6La0
        guEQRuPP36fBdR6fT4yy57Rp9LON03579Yz0YKYLUGoADWnv9fyirhr+BonZ6Zqm
        HiKwF80CgYAjRguz6TpKViQKOUHUc5oKXRouysw4/0Tbxv15lLIWMVjbVX2xz13g
        mHRwYixWdiLolgw/kwuzZ4wcZpIyn4TRK66UyTSG7LnY2Eh9xs6ZHLLHxDUNgHk6
        Ob9JCpapUTY7oTo7oOIU9flKRMmg+UOR4ZwZZ1KLjqDhX/4rcmYOtQ==
        -----END RSA PRIVATE KEY-----""";

    public static final KeyPair keyPair = loadKeyPair();

    RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

    public TestTokenUtil() {
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
        return createAccessToken(issuerId, "1adc931e-d65f-4357-b90d-dd4131b8749a",
                                 "marissa", "marissa@test.com", validitySeconds, clientScopes, requestedScopes, "cf",
                                 resourceIds,
                                 "passsword", null, null, issuedAtMillis, "uaa");
    }

    public Authentication mockAuthentication(final int validitySeconds, final String zoneUserScope) {
        Collection<GrantedAuthority> clientScopes = Arrays.asList(new GrantedAuthority[] {
            new SimpleGrantedAuthority("uaa.resource"), new SimpleGrantedAuthority(zoneUserScope)
        });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList(new String[] { "openid", zoneUserScope }));
        Set<String> resourceIds = new HashSet<>(Arrays.asList(new String[] { "none" }));
        String openIdToken = createAccessToken(TOKEN_ISSUER_ID,
                                               "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa", "marissa@test.com",
                                               validitySeconds, clientScopes,
                                               requestedScopes, "cf", resourceIds, "passsword", null,
                                               null, System.currentTimeMillis(),
                                               "uaa");
        return new BearerTokenAuthenticationToken(openIdToken);
    }

    public String mockAccessToken(final String issuerId, final int validitySeconds, final String zoneUserScope) {
        Collection<GrantedAuthority> clientScopes = Arrays.asList(new GrantedAuthority[] {
            new SimpleGrantedAuthority("uaa.resource"), new SimpleGrantedAuthority(zoneUserScope)
        });
        Set<String> requestedScopes = new HashSet<>(Arrays.asList("openid", zoneUserScope));
        Set<String> resourceIds = new HashSet<>(Arrays.asList("none"));
        return createAccessToken(issuerId,
                                 "1adc931e-d65f-4357-b90d-dd4131b8749a", "marissa",
                                 "marissa@test.com", validitySeconds, clientScopes,
                                 requestedScopes, "cf", resourceIds, "passsword", null,
                                 null, System.currentTimeMillis(),
                                 "uaa");
    }

    private String createAccessToken(final String issuerId, final String userId,
                                     final String username, final String userEmail, final int validitySeconds,
                                     final Collection<GrantedAuthority> clientScopes, final Set<String> requestedScopes,
                                     final String clientId,
                                     final Set<String> resourceIds, final String grantType,
                                     final Map<String, String> additionalAuthorizationAttributes,
                                     final String revocableHashSignature, final long issuedAtMillis,
                                     final String zoneId) {

            Instant now = Instant.now();
        Map<String, Object> info = new HashMap<>();
        if (null != additionalAuthorizationAttributes) {
            info.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }

        String compact =
            Jwts.builder().claims().issuer("http://trusted.issuer/oauth/token").subject(userId).audience().add(username)
                .and().add(SCOPE, requestedScopes)
                .add(AUTHORITIES, clientScopes.stream().map(GrantedAuthority::getAuthority).collect(
                    Collectors.toSet())).add(AUD, resourceIds).add(CLIENT_ID, clientId)
                .add(CID, clientId).add(AZP, clientId).add(GRANT_TYPE, grantType)
                .add(REVOCATION_SIGNATURE, revocableHashSignature)
                .add(ZONE_ID, zoneId).add(USER_ID, userId).add(USER_NAME, username)
                .add(EMAIL, userEmail)
                .issuer(issuerId)
                .issuer("http://trusted.issuer/oauth/token")
                .expiration(Date.from(now.plus(5L, ChronoUnit.MINUTES)))
                .issuedAt(Date.from(now))
                .and().signWith(getPrivateKey(), SIG.RS256)
                .compact();
        return compact;
          }

    private static KeyPair loadKeyPair() {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return keyPairGenerator.genKeyPair();
    }

    private static PrivateKey getPrivateKey() {
        String rsaPrivateKey = UPDATED_TOKEN_SIGNING_KEY.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END RSA PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replaceAll("\\s", "").replaceAll("\n", "");
        System.out.println(rsaPrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static ResponseEntity<String> mockTokenKeyResponseEntity() {
        Map<String, Object> responseEntityBody = new HashMap<>();
        responseEntityBody.put("alg", "SHA256withRSA");
        responseEntityBody.put("value", TOKEN_VERIFYING_KEY);
        responseEntityBody.put("kty", "RSA");
        responseEntityBody.put("use", "sig");
        responseEntityBody.put("n",
                               "ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZ"
                               +
                               "eAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feV"
                               +
                               "P9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tV"
                               + "kkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=");
        responseEntityBody.put("e", "AQAB");
        return new ResponseEntity<>(new Gson().toJson(responseEntityBody), HttpStatus.OK);
    }

    public static ResponseEntity<String> mockUpdatedTokenKeyResponseEntity() {
        Map<String, Object> responseEntityBody = new HashMap<>();
        responseEntityBody.put("alg", "SHA256withRSA");
        responseEntityBody.put("value", UPDATED_TOKEN_VERIFYING_KEY);
        responseEntityBody.put("kty", "RSA");
        responseEntityBody.put("use", "sig");
        responseEntityBody.put("n",
                               "ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtNdsfasf3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZ"
                               +
                               "eAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feV"
                               +
                               "P9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tV"
                               + "kkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=");
        responseEntityBody.put("e", "AQAB");
        return new ResponseEntity<>(new Gson().toJson(responseEntityBody), HttpStatus.OK);
    }
}
