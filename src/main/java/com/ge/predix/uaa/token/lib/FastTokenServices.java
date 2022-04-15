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

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.ge.predix.uaa.token.lib.exceptions.IssuerNotTrustedException;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

/**
 * FastRemotetokenServices is a replacement for the original RemoteTokenServices. It is "fast" because it does not
 * make calls to UAA's /check_token endpoint every time it verifies a token. Instead, it uses UAA's token signing key,
 * fetched at startup, to verify the token.
 */
public class FastTokenServices implements ResourceServerTokenServices, InitializingBean {

    private static final long DEFAULT_TTL_24HR_MILLIS = 86400000L;

    private static final Log LOG = LogFactory.getLog(FastTokenServices.class);

    private RestOperations restTemplate;

    private boolean storeClaims = false;

    private boolean useHttps = true;

    private int maxAcceptableClockSkewSeconds = 60;

    private int tokenKeyRequestTimeoutSeconds = 2;

    private long issuerPublicKeyTTLMillis = DEFAULT_TTL_24HR_MILLIS;

    private List<String> trustedIssuers;

    private LoadingCache<String, SignatureVerifier> tokenKeys;

    /**
     * Creates the FastTokenServices with {@link FastTokenServices#DEFAULT_TTL_24HR_MILLIS}.
     */
    public FastTokenServices() {
        initTokenKeysCache(DEFAULT_TTL_24HR_MILLIS);
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
                .build(k -> computeSignatureVerifier(k));
    }

    public void setTokenKeyRequestTimeout(final int tokenKeyRequestTimeout) {
        this.tokenKeyRequestTimeoutSeconds = tokenKeyRequestTimeout;
    }

    public SignatureVerifier computeSignatureVerifier(final String iss) {
        String tokenKey = getTokenKey(iss);
        SignatureVerifier verifier = getVerifier(tokenKey);
        return verifier;
    }

    @Override
    public OAuth2Authentication loadAuthentication(final String accessToken)
            throws AuthenticationException, InvalidTokenException {

        if (StringUtils.isEmpty(accessToken)) {
            LOG.error("Access token is null or empty.");
            throw new InvalidTokenException("Malformed Access Token");
        }

        Map<String, Object> claims;
        try {
            claims = getTokenClaims(accessToken);
        } catch (IllegalArgumentException e) {
            LOG.error("Malformed Access Token: " + accessToken);
            LOG.error(e);
            throw new InvalidTokenException("Malformed Access Token", e);
        }
        String iss = getIssuerFromClaims(claims);

        verifyIssuer(iss);
        /*
        getIfPresent() will perform the lookup, which may be null. Then the thread computes the value, which is
        expensive (hence the cache) and inserts it. This allows for a race where two threads query for the key,
        compute, and insert. This is known as a cache stampede.

        get(key, function) will atomically compute the value when absent. This acquires a per-entry lock so that only
        one thread does the work, subsequent calls block, and all receive the result. This is known as memoization.

        Caffeine's get will perform a lock-free getIfPresent followed by a blocking computeIfAbsent, which avoids lock
        contention and duplicate computation work. We try to promote this style (hence get is shorter) and offer
        LoadingCache with additional functionality if you provide the computation function upfront.

        Inorder to use the lambda functions functionality of cache we need to upgrade java version to 1.8 on
        spring-jwt-validator.
         */
        SignatureVerifier verifier = this.tokenKeys.get(iss);
        // check if the signatureVerifier for that issuer is already in the cache

        JwtHelper.decodeAndVerify(accessToken, verifier);
        verifyTimeWindow(claims);

        Assert.state(claims.containsKey(Claims.CLIENT_ID), "Client id must be present in response from auth server");
        String remoteClientId = (String) claims.get(Claims.CLIENT_ID);

        Set<String> scope = new HashSet<>();
        if (claims.containsKey(Claims.SCOPE)) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) claims.get(Claims.SCOPE);
            scope.addAll(values);
        }

        AuthorizationRequest clientAuthentication = new AuthorizationRequest(remoteClientId, scope);

        if (claims.containsKey("resource_ids") || claims.containsKey("client_authorities")) {
            Set<String> resourceIds = new HashSet<>();
            if (claims.containsKey("resource_ids")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) claims.get("resource_ids");
                resourceIds.addAll(values);
            }

            Set<GrantedAuthority> clientAuthorities = new HashSet<>();
            if (claims.containsKey("client_authorities")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) claims.get("client_authorities");
                clientAuthorities.addAll(getAuthorities(values));
            }

            BaseClientDetails clientDetails = new BaseClientDetails();
            clientDetails.setClientId(remoteClientId);
            clientDetails.setResourceIds(resourceIds);
            clientDetails.setAuthorities(clientAuthorities);
            clientAuthentication.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);
        }

        Map<String, String> requestParameters = new HashMap<>();
        if (isStoreClaims()) {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                if (entry.getValue() != null && entry.getValue() instanceof String) {
                    requestParameters.put(entry.getKey(), (String) entry.getValue());
                }
            }
        }

        if (claims.containsKey(Claims.ADDITIONAL_AZ_ATTR)) {
            try {
                requestParameters.put(Claims.ADDITIONAL_AZ_ATTR,
                        JsonUtils.writeValueAsString(claims.get(Claims.ADDITIONAL_AZ_ATTR)));
            } catch (JsonUtils.JsonUtilException e) {
                throw new IllegalStateException("Cannot convert access token to JSON", e);
            }
        }
        clientAuthentication.setRequestParameters(Collections.unmodifiableMap(requestParameters));

        Authentication userAuthentication = getUserAuthentication(claims, scope);

        clientAuthentication.setApproved(true);
        return new OAuth2Authentication(clientAuthentication.createOAuth2Request(), userAuthentication);
    }

    private void verifyIssuer(final String iss) {
        Assert.notEmpty(this.trustedIssuers, "Trusted issuers must be defined for authentication.");

        if (!this.trustedIssuers.contains(iss)) {
            throw new IssuerNotTrustedException("The issuer '" + iss + "' is not trusted "
                    + "because it is not in the configured list of trusted issuers.");
        }
    }

    void verifyTimeWindow(final Map<String, Object> claims) {

        Date iatDate = null;
        Date expDate = null;
        try {
            iatDate = getIatDate(claims);
            expDate = getExpDate(claims);
        } catch (Exception e) {
            throw new InvalidTokenException("Unable to determine token validity window.");
        }

        Date currentDate = new Date();
        if (iatDate != null && iatDate.after(currentDate)) {
            throw new InvalidTokenException(String.format(
                    "Token validity window is in the future. Token is issued at [%s]. Current date is [%s]",
                    iatDate.toString(), currentDate.toString()));
        }

        if (expDate != null && expDate.before(currentDate)) {
            throw new InvalidTokenException(
                    String.format("Token is expired. Expiration date is [%s]. Current date is [%s]", expDate.toString(),
                            currentDate.toString()));
        }
    }

    private Date getIatDate(final Map<String, Object> claims) {
        long iat = Long.valueOf(claims.get(Claims.IAT).toString());
        return new Date((iat - this.maxAcceptableClockSkewSeconds) * 1000L);
    }

    private Date getExpDate(final Map<String, Object> claims) {
        long exp = Long.valueOf(claims.get(Claims.EXP).toString());
        return new Date((exp + this.maxAcceptableClockSkewSeconds) * 1000L);
    }

    protected String getTokenKey(final String issuer) {
        // Check if the RestTemplate has been initialized already...
        if (null == this.restTemplate) {
            this.restTemplate = new RestTemplate();
            ((RestTemplate) this.restTemplate).setErrorHandler(new FastTokenServicesResponseErrorHandler());
            HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
            requestFactory.setConnectTimeout(this.tokenKeyRequestTimeoutSeconds * 1000);
            ((RestTemplate) this.restTemplate).setRequestFactory(requestFactory);
        }

        String tokenKeyUrl = getTokenKeyURL(issuer);
        ParameterizedTypeReference<Map<String, Object>> typeRef = new ParameterizedTypeReference<Map<String, Object>>()
        {
            //
        };
        Map<String, Object> responseMap = null;
        try {
            responseMap = this.restTemplate.exchange(tokenKeyUrl, HttpMethod.GET, null, typeRef).getBody();
        } catch (Exception e) {
            LOG.error("Unable to retrieve the token public key. " + e.getMessage());
            throw e;
        }

        String tokenKey = responseMap.get("value").toString();

        if (LOG.isDebugEnabled()) {
            LOG.debug("The downloaded token key from '" + tokenKeyUrl + "' is: '" + tokenKey + "'");
        }

        return tokenKey;

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

    protected Set<GrantedAuthority> getAuthorities(final Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }

    protected Authentication getUserAuthentication(final Map<String, Object> map, final Set<String> scope) {
        String username = (String) map.get(Claims.USER_NAME);
        if (null == username) {
            String clientId = (String) map.get(Claims.CLIENT_ID);

            if (null == clientId) {
                return null;
            }

            Set<GrantedAuthority> clientAuthorities = new HashSet<>();
            clientAuthorities.addAll(getAuthorities(scope));
            clientAuthorities.add(new SimpleGrantedAuthority("isOAuth2Client"));
            return new RemoteUserAuthentication(clientId, clientId, null, clientAuthorities);
        }
        Set<GrantedAuthority> userAuthorities = new HashSet<>();
        if (map.containsKey("user_authorities")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) map.get("user_authorities");
            userAuthorities.addAll(getAuthorities(values));
        } else {
            // User authorities had better not be empty or we might mistake user
            // for unauthenticated
            userAuthorities.addAll(getAuthorities(scope));
        }
        String email = (String) map.get(Claims.EMAIL);
        String id = (String) map.get(Claims.USER_ID);
        return new RemoteUserAuthentication(id, username, email, userAuthorities);
    }

    protected String getAuthorizationHeader(final String clientId, final String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    protected Map<String, Object> getTokenClaims(final String accessToken) {
        Jwt token = JwtHelper.decode(accessToken);
        Map<String, Object> claims = JsonUtils.readValue(token.getClaims(), new TypeReference<Map<String, Object>>() {
            // Nothing to add here.
        });
        return claims;
    }

    protected String getIssuerFromClaims(final Map<String, Object> claims) {
        return claims.get(Claims.ISS).toString();
    }

    private static SignatureVerifier getVerifier(final String signingKey) {
        if (isAssymetricKey(signingKey)) {
            return new RsaVerifier(signingKey);
        }

        throw new IllegalArgumentException("Unsupported key detected. "
                + "FastRemoteTokenService only supports RSA public keys for token verification.");
    }

    /**
     * @return true if the key has a public verifier
     */
    private static boolean isAssymetricKey(final String key) {
        return key.startsWith("-----BEGIN PUBLIC KEY-----");
    }

    @Override
    public OAuth2AccessToken readAccessToken(final String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    public void setRestTemplate(final RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean isStoreClaims() {
        return this.storeClaims;
    }

    public void setStoreClaims(final boolean storeClaims) {
        this.storeClaims = storeClaims;
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
}