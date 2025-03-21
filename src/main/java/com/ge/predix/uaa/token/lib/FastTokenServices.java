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

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * FastRemotetokenServices is a replacement for the original RemoteTokenServices. It is "fast" because it does not
 * make calls to UAA's /check_token endpoint every time it verifies a token. Instead, it uses UAA's token signing key,
 * fetched at startup, to verify the token.
 */
public class FastTokenServices implements AuthenticationProvider, InitializingBean {

    private static final long DEFAULT_TTL_24HR_MILLIS = 86400000L;

    private static final Log LOG = LogFactory.getLog(FastTokenServices.class);

    private RestOperations restTemplate;

    private boolean useHttps = true;

    private int maxAcceptableClockSkewSeconds = 60;

    private int tokenKeyRequestTimeoutSeconds = 2;

    private long issuerPublicKeyTTLMillis = DEFAULT_TTL_24HR_MILLIS;

    private List<String> trustedIssuers;

    private LoadingCache<String, RSASSAVerifier> tokenKeys;

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = null;

    /**
     * Creates the FastTokenServices with {@link FastTokenServices#DEFAULT_TTL_24HR_MILLIS}.
     */
    public FastTokenServices() {
        initTokenKeysCache(DEFAULT_TTL_24HR_MILLIS);
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtAuthenticationConverter = new JwtAuthenticationConverter();
        ((JwtAuthenticationConverter) jwtAuthenticationConverter).setJwtGrantedAuthoritiesConverter(
            grantedAuthoritiesConverter);

    }

    /**
     * @param issuerPublicKeyTTLMillis A value of Long.MAX_VALUE implies cache never expires.
     */
    public FastTokenServices(final long issuerPublicKeyTTLMillis) {
        initTokenKeysCache(issuerPublicKeyTTLMillis);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        initTokenKeysCache(issuerPublicKeyTTLMillis);
    }

    private void initTokenKeysCache(final long ttlMillis) {
     /*
        Memory leak was identified in performance tests due to a lazy expiration mechanism in passive expiring map.
        Even though we were initializing passive expiring map with TTL, the entries were not flushed unless a get
        () call is made on the expired entries or a call that prompts entire map scan, for example size(). This
        could lead to a memory leak as expired entry might never be retrieved.

        For instance, when loadAuthentication call is made it adds the signature verifier for the token issuer in
        tokenKeys map. This entry is not removed upon expiration unless another loadAuthentication call made after
        the expired time with the access token from the same issuer. Abandoned issuers will be stuck in the cache.

        We have decide to use caffeine as the caching solution to address the memory leak.
     */
        this.tokenKeys = Caffeine.newBuilder().expireAfterWrite(ttlMillis, TimeUnit.MILLISECONDS)
                .build(this::computeSignatureVerifier);
    }

    public void setTokenKeyRequestTimeout(final int tokenKeyRequestTimeout) {
        this.tokenKeyRequestTimeoutSeconds = tokenKeyRequestTimeout;
    }

    public RSASSAVerifier computeSignatureVerifier(final String iss) throws ParseException, JOSEException {
        String tokenKey = getTokenKey(iss);
        return getVerifier(tokenKey);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        LOG.debug("Authenticating the access token.");
        String accessToken = ((BearerTokenAuthenticationToken) authentication).getToken();
        if (ObjectUtils.isEmpty(accessToken)) {
            LOG.error("Access token is null or empty.");
            throw new InvalidBearerTokenException("Malformed Access Token");
        }
        Map<String, Object> claims;
        SignedJWT jwsObject;
        JwtDecoder jwtDecoder;
        try {
            jwsObject = SignedJWT.parse(accessToken);
            claims = getTokenClaims(jwsObject);
            String iss = getIssuerFromClaims(claims);
            verifyIssuer(iss);
            RSASSAVerifier verifier = tokenKeys.get(iss);
            if (verifier != null && jwsObject.verify(verifier)) {
                jwtDecoder = NimbusJwtDecoder.withPublicKey(verifier.getPublicKey()).build();
                LOG.debug("Access token is valid.");
            } else {
                throw new RuntimeException("Unable to fetch public key for issuer: " + iss);
            }
        } catch (IllegalArgumentException | ParseException e) {
            LOG.error("Malformed Access Token: " + accessToken);
            LOG.error(e);
            throw new InvalidBearerTokenException("Malformed Access Token", e);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwtDecoder.decode(accessToken));
        if (token != null && token.getDetails() == null) {
            token.setDetails(authentication.getDetails());
            token.setAuthenticated(true);
        } else {
            throw new InvalidBearerTokenException("Invalid Access Token");
        }
        LOG.debug("Authentication successful.");
        return token;
    }

    protected void verifyIssuer(final String iss) {
        Assert.notEmpty(this.trustedIssuers, "Trusted issuers must be defined for authentication.");

        if (!this.trustedIssuers.contains(iss)) {
            throw new InvalidBearerTokenException("The issuer '" + iss + "' is not trusted "
                    + "because it is not in the configured list of trusted issuers.");
        }
    }

    protected String getTokenKey(final String issuer) {
        LOG.debug("Retrieving the token key for issuer: " + issuer);
        // Check if the RestTemplate has been initialized already...
        if (null == this.restTemplate) {
            this.restTemplate = new RestTemplate();
            ((RestTemplate) this.restTemplate).setErrorHandler(new FastTokenServicesResponseErrorHandler());
            HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
            requestFactory.setConnectTimeout(this.tokenKeyRequestTimeoutSeconds * 1000);
            ((RestTemplate) this.restTemplate).setRequestFactory(requestFactory);
        }
        String tokenKeyUrl = getTokenKeyURL(issuer);
        String response;
        try {
            response = this.restTemplate.exchange(tokenKeyUrl, HttpMethod.GET, null, String.class).getBody();
        } catch (Exception e) {
            LOG.error("Unable to retrieve the token public key. ", e);
            throw e;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("The downloaded token key from '" + tokenKeyUrl + "' is: '" + response + "'");
        }
        LOG.debug("Token key retrieved successfully.");
        return response;
    }

    protected String getTokenKeyURL(final String issuer) {
        if (issuer == null) {
            return null;
        }

        String regexPattern = "^(http.*)/oauth/token$";
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(issuer);
        if (!matcher.matches()) {
            throw new IllegalStateException("FastRemoteTokenService cannot process token with issuer id '" + issuer
                    + "' because it does not match the regular expression '" + regexPattern + "'.");
        }
        String issuerPart = matcher.group(1);

        String scheme = "https";
        if (!this.useHttps) {
            scheme = "http";
        }
        return UriComponentsBuilder.fromUriString(issuerPart).scheme(scheme).pathSegment("token_key").build()
                .toUriString();
    }

    protected Map<String, Object> getTokenClaims(final SignedJWT signedJWT) throws ParseException {
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        return claims.getClaims();
    }

    protected String getIssuerFromClaims(final Map<String, Object> claims) {
        return claims.get(Claims.ISS).toString();
    }

    private static RSASSAVerifier getVerifier(final String signingKey) throws ParseException, JOSEException {
        return new RSASSAVerifier(JWK.parse(signingKey).toRSAKey());
    }

    public void setJwtAuthenticationConverter(final JwtAuthenticationConverter jwtAuthenticationConverter) {
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    public void setRestTemplate(final RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setUseHttps(final boolean useHttps) {
        this.useHttps = useHttps;
    }

    public void setMaxAcceptableClockSkewSeconds(final int maxAcceptableClockSkewSeconds) {
        this.maxAcceptableClockSkewSeconds = maxAcceptableClockSkewSeconds;
    }

    public void setTrustedIssuers(final List<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    public void setIssuerPublicKeyTTLMillis(final long ttlMillis) {
        this.issuerPublicKeyTTLMillis = ttlMillis;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}