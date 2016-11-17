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

import static com.ge.predix.uaa.token.lib.Claims.EXP;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

/**
 * FastRemotetokenServices is a replacement for the original RemoteTokenServices. It is "fast" because it does not
 * make calls to UAA's /check_token endpoint every time it verifies a token. Instead, it uses UAA's token signing key,
 * fetched at startup, to verify the token.
 *
 */
public class FastTokenServices implements ResourceServerTokenServices {

    private static final Log LOG = LogFactory.getLog(FastTokenServices.class);

    private RestOperations restTemplate;

    private boolean storeClaims = false;

    private boolean useHttps = true;

    private int maxAcceptableClockSkewSeconds = 60;

    private int tokenKeyRequestTimeoutSeconds = 2;

    private List<String> trustedIssuers;

    private final Map<String, SignatureVerifier> tokenKeys = new HashMap<>();

    // public FastTokenServices() {}//Default constructor not needed

    public void setTokenKeyRequestTimeout(final int tokenKeyRequestTimeout) {
        this.tokenKeyRequestTimeoutSeconds = tokenKeyRequestTimeout;
    }

    @Override
    public OAuth2Authentication loadAuthentication(final String accessToken) throws AuthenticationException {
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

        // check if the singerProvider for that issuer has already in the cache
        SignatureVerifier verifier = this.tokenKeys.get(iss);
        if (null == verifier) {
            String tokenKey = getTokenKey(iss);
            verifier = getVerifier(tokenKey);
            this.tokenKeys.put(iss, verifier);
        }

        JwtHelper.decodeAndVerify(accessToken, verifier);
        verifyTimeWindow(claims);

        Assert.state(claims.containsKey("client_id"), "Client id must be present in response from auth server");
        String remoteClientId = (String) claims.get("client_id");

        Set<String> scope = new HashSet<>();
        if (claims.containsKey("scope")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) claims.get("scope");
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

        if ((null != this.trustedIssuers) && (0 < this.trustedIssuers.size())) {
            if (!this.trustedIssuers.contains(iss)) {
                throw new InvalidTokenException("The issuer '" + iss + "' is not trusted "
                        + "because it is not in the configured list of trusted issuers: " + this.trustedIssuers + ".");
            }

            return;
        }
    }

    private void verifyTimeWindow(final Map<String, Object> claims) {

        Date iatDate = getIatDate(claims);
        Date expDate = getExpDate(claims);

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

    protected Date getIatDate(final Map<String, Object> claims) {
        Integer iat = (Integer) claims.get("iat");
        return new Date((iat.longValue() - this.maxAcceptableClockSkewSeconds) * 1000L);
    }

    protected Date getExpDate(final Map<String, Object> claims) {
        Integer exp = (Integer) claims.get(EXP);
        return new Date((exp.longValue() + this.maxAcceptableClockSkewSeconds) * 1000L);
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
        } catch (RestClientException e) {
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
        String username = (String) map.get("user_name");
        if (null == username) {
            String clientId = (String) map.get("client_id");

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
        String email = (String) map.get("email");
        String id = (String) map.get("user_id");
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
        if (StringUtils.isEmpty(accessToken)) {
            return null;
        }

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
}
