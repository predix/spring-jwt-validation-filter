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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriUtils;

/**
 *
 * @author 212304931
 */
public abstract class AbstractZoneAwareTokenService implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractZoneAwareTokenService.class);

    // Return this message when zone doesn't exist AND when scopes are invalid for a zone so that a malicious user
    // cannot figure out which zones do/do not exist in a service
    private static final String UNAUTHORIZE_MESSAGE = "Unauthorized access for zone: '%s'.";

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final DefaultZoneConfiguration defaultZoneConfig;

    private FastTokenServices defaultFastTokenService;

    private final HttpServletRequest request;

    private List<String> serviceZoneHeadersList = List.of("Predix-Zone-Id");

    private List<String> serviceBaseDomainList;

    private boolean useSubdomainsForZones = true;

    private final String serviceId;

    private boolean useHttps = true;

    private FastTokenServicesCreator fastRemoteTokenServicesCreator = new FastTokenServicesCreator();

    public AbstractZoneAwareTokenService(final String serviceId, final DefaultZoneConfiguration defaultZoneConfig,
                                         final HttpServletRequest request) {
        this.serviceId = serviceId;
        this.defaultZoneConfig = defaultZoneConfig;
        this.request = request;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(final Authentication authentication)
            throws AuthenticationException {
        LOGGER.debug("Authenticating token for service: {}", this.serviceId);
        // Get zone id being requested from HTTP request
        String zoneId = HttpServletRequestUtil.getZoneName(this.request, this.getServiceBaseDomainList(),
                                                           this.getServiceZoneHeadersList(),
                                                           this.useSubdomainsForZones);
        String requestUri = this.request.getRequestURI();
        Authentication authenticationResponse;
        if (isNonZoneSpecificRequest(requestUri)) {
            if (zoneId == null) {
                authenticationResponse = authenticateNonZoneSpecificRequest(authentication);
            } else {
                throw new InvalidBearerTokenException("Resource not available for specified zone: " + zoneId);
            }
        } else {
            if (zoneId == null) {
                throw new InvalidBearerTokenException("No zone specified for zone specific request:  " + requestUri);
            } else {
                try {
                    authenticationResponse = authenticateZoneSpecificRequest(authentication, zoneId);
                } catch (HttpStatusCodeException e) {
                    // Translate 404 from ZAC into InvalidRequestException
                    if (e.getStatusCode() != HttpStatus.NOT_FOUND) {
                        throw e;
                    }
                    throw new InvalidBearerTokenException(UNAUTHORIZE_MESSAGE.formatted(zoneId));
                }
            }
        }
        LOGGER.debug("Token authenticated for service: {}", this.serviceId);
        return authenticationResponse;
    }

    private Authentication authenticateNonZoneSpecificRequest(final Authentication accessToken) {
        Authentication authentication;
        if (this.defaultFastTokenService == null) {
            this.defaultFastTokenService = createFastTokenService(this.defaultZoneConfig.getTrustedIssuerIds());
        }
        authentication = this.defaultFastTokenService.authenticate(accessToken);
        return authentication;
    }

    private Authentication authenticateZoneSpecificRequest(final Authentication accessToken, final String zoneId) {
        LOGGER.debug("Authenticating token for zone: {}", zoneId);
        Authentication authentication;
        FastTokenServices tokenServices = getOrCreateZoneTokenService(zoneId);
        authentication = tokenServices.authenticate(accessToken);
        assertUserZoneAccess((AbstractAuthenticationToken) authentication, zoneId);

        // Decorate authentication object with zoneId
        authentication = new ZoneOAuth2Authentication((JwtAuthenticationToken) authentication, zoneId);
        LOGGER.debug("Token authenticated for zone: {}", zoneId);
        return authentication;
    }

    private boolean isNonZoneSpecificRequest(final String requestUri) {
        boolean result = false;

        String normalizedUri = normalizeUri(requestUri);

        if (this.defaultZoneConfig.getAllowedUriPatterns() != null) {
            for (String pattern : this.defaultZoneConfig.getAllowedUriPatterns()) {
                if (this.pathMatcher.match(pattern, normalizedUri)) {
                    result = true;
                    break;
                }
            }
        }

        return result;
    }

    String normalizeUri(final String requestUri) {
        LOGGER.debug("Normalizing request URI: {}", requestUri);
        String normalizedUri = null;
        try {
            // Decode request URI to resolve percent-encoded special characters.
            // For example, "/v1/hello/%2e%2e/policy-set/my%20policy" --> "/v1/hello/../policy-set/my policy"
            String decodedUri = UriUtils.decode(requestUri, StandardCharsets.UTF_8.name());

            // Encode URI again to percent-encode "non-friendly" characters that cause URISyntaxException.
            // For example, "/v1/hello/../policy-set/my policy" --> "/v1/hello/../policy-set/my%20policy"
            String encodedUri = UriUtils.encodePath(decodedUri, StandardCharsets.UTF_8.name());

            // Normalize URI to resolve relative paths:
            // For example, "/v1/hello/../policy-set/my%20policy" --> "/v1/policy-set/my%20policy"
            normalizedUri = new URI(encodedUri).normalize().toString();
        } catch (URISyntaxException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unable to normalize request URL: " + requestUri,
                                              e);
        }
        LOGGER.debug("Normalized request URI: {}", normalizedUri);
        return normalizedUri;
    }

    protected abstract FastTokenServices getOrCreateZoneTokenService(final String zoneId);

    private void assertUserZoneAccess(final AbstractAuthenticationToken authentication, final String zoneId) {
        Collection<? extends GrantedAuthority> authenticationAuthorities = authentication.getAuthorities();
        String expectedScope = this.serviceId + ".zones." + zoneId + ".user";

        if (!authenticationAuthorities.contains(new SimpleGrantedAuthority(expectedScope))) {
            LOGGER.debug("Invalid token scope. Did not find expected scope: " + expectedScope);
            throw new InvalidBearerTokenException(UNAUTHORIZE_MESSAGE.formatted(zoneId));
        }
    }

    protected FastTokenServices createFastTokenService(final List<String> trustedIssuers) {
        LOGGER.debug("Creating FastTokenServices for service: {}", this.serviceId);
        FastTokenServices tokenServices;
        //Create FastTokenServices with indefinite caching of public keys, since the tokenServices are cached here 
        //with a TTL.
        tokenServices = this.fastRemoteTokenServicesCreator.newInstance();
        tokenServices.setUseHttps(this.useHttps);
        tokenServices.setTrustedIssuers(trustedIssuers);
        LOGGER.debug("FastTokenServices created for service: {}", this.serviceId);
        return tokenServices;
    }

    public String getServiceId() {
        return this.serviceId;
    }

    public void setFastRemoteTokenServicesCreator(final FastTokenServicesCreator fastRemoteTokenServicesCreator) {
        this.fastRemoteTokenServicesCreator = fastRemoteTokenServicesCreator;
    }


    public boolean isUseHttps() {
        return this.useHttps;
    }

    public void setUseHttps(final boolean useHttps) {
        this.useHttps = useHttps;
    }

    public FastTokenServices getDefaultFastTokenService() {
        return this.defaultFastTokenService;
    }

    public void setDefaultFastTokenService(final FastTokenServices defaultFastTokenService) {
        this.defaultFastTokenService = defaultFastTokenService;
    }

    public void setServiceBaseDomain(final String serviceBaseDomain) {
        this.serviceBaseDomainList = splitCSV(serviceBaseDomain);
    }

    public void setServiceZoneHeaders(final String serviceZoneHeaders) {
        this.serviceZoneHeadersList = splitCSV(serviceZoneHeaders);
    }

    private List<String> splitCSV(final String csvString) {
        if (!StringUtils.isBlank(csvString)) {
            return Arrays.asList(csvString.split(","));
        } else {
            return Collections.emptyList();
        }
    }

    public List<String> getServiceZoneHeadersList() {
        return this.serviceZoneHeadersList;
    }

    public List<String> getServiceBaseDomainList() {
        return this.serviceBaseDomainList;
    }

    public void setUseSubdomainsForZones(final boolean useSubdomainsForZones) {
        this.useSubdomainsForZones = useSubdomainsForZones;
    }

    public boolean isUseSubdomainsForZones() {
        return this.useSubdomainsForZones;
    }
}
