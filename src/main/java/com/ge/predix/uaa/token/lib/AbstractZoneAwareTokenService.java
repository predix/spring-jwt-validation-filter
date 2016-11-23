/*
 * Copyright 2015, 2016015 General Electric Company. All rights reserved.
 *
 * The copyright to the computer software herein is the property of
 * General Electric Company. The software may be used and/or copied only
 * with the written permission of General Electric Company or in accordance
 * with the terms and conditions stipulated in the agreement/contract
 * under which the software has been supplied.
 */

package com.ge.predix.uaa.token.lib;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.HttpStatusCodeException;

/**
 *
 * @author 212304931
 */
public abstract class AbstractZoneAwareTokenService implements ResourceServerTokenServices {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractZoneAwareTokenService.class);

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private DefaultZoneConfiguration defaultZoneConfig;

    private FastTokenServices defaultFastTokenService;

    private FastTokenServicesCreator fastRemoteTokenServicesCreator = new FastTokenServicesCreator();

    @Autowired(required = true)
    private HttpServletRequest request;

    private List<String> serviceZoneHeadersList = Arrays.asList("Predix-Zone-Id");

    private List<String> serviceBaseDomainList;

    private String serviceId;

    private boolean storeClaims = false;

    private boolean useHttps = true;

    @Override
    public OAuth2Authentication loadAuthentication(final String accessToken)
            throws AuthenticationException, InvalidTokenException {

        // Get zone id being requested from HTTP request
        String zoneId = HttpServletRequestUtil.getZoneName(this.request, this.getServiceBaseDomainList(),
                this.getServiceZoneHeadersList());

        URI requestUri = URI.create(this.request.getRequestURI());

        OAuth2Authentication authentication;
        if (isNonZoneSpecificRequest(requestUri)) {
            if (zoneId == null) {
                authentication = authenticateNonZoneSpecificRequest(accessToken);
            } else {
                throw new InvalidRequestException("Resource not available for specified zone: " + zoneId);
            }
        } else {
            if (zoneId == null) {
                throw new InvalidRequestException("No zone specified for zone specific request:  " + requestUri);
            } else {
                try {
                    authentication = authenticateZoneSpecificRequest(accessToken, zoneId);
                } catch (HttpStatusCodeException e) {
                    // Translate 404 from ZAC into InvalidRequestException
                    if (e.getStatusCode() != HttpStatus.NOT_FOUND) {
                        throw e;
                    }
                    throw new InvalidRequestException(
                            "Authentication of request for zone " + zoneId + " failed.");
                }
            }
        }

        return authentication;
    }

    private OAuth2Authentication authenticateNonZoneSpecificRequest(final String accessToken) {
        OAuth2Authentication authentication;
        if (this.defaultFastTokenService == null) {
            this.defaultFastTokenService = createFastTokenService(this.defaultZoneConfig.getTrustedIssuerIds());
        }
        authentication = this.defaultFastTokenService.loadAuthentication(accessToken);
        return authentication;
    }

    private OAuth2Authentication authenticateZoneSpecificRequest(final String accessToken, final String zoneId) {
        OAuth2Authentication authentication;
        FastTokenServices tokenServices = getOrCreateZoneTokenService(zoneId);
        authentication = tokenServices.loadAuthentication(accessToken);
        assertUserZoneAccess(authentication, zoneId);

        // Decorate authentication object with zoneId
        authentication = new ZoneOAuth2Authentication(authentication.getOAuth2Request(), authentication, zoneId);
        return authentication;
    }

    private boolean isNonZoneSpecificRequest(final URI requestUri) {
        boolean result = false;

        String requestUriString = requestUri.normalize().toString();

        if (this.defaultZoneConfig.getAllowedUriPatterns() != null) {
            for (String pattern : this.defaultZoneConfig.getAllowedUriPatterns()) {
                if (this.pathMatcher.match(pattern, requestUriString)) {
                    result = true;
                    break;
                }
            }
        }

        return result;
    }

    protected abstract FastTokenServices getOrCreateZoneTokenService(final String zoneId);

    private void assertUserZoneAccess(final OAuth2Authentication authentication, final String zoneId) {
        Collection<? extends GrantedAuthority> authenticationAuthorities = authentication.getAuthorities();
        String expectedScope = this.serviceId + ".zones." + zoneId + ".user";

        if (!authenticationAuthorities.contains(new SimpleGrantedAuthority(expectedScope))) {
            LOGGER.debug("Invalid token scope. Did not find expected scope: " + expectedScope);
            // This exception is translated to HTTP 401. InsufficientAuthenticationException results in 500
            throw new InvalidTokenException(String.format("Unauthorized zone access by principal: %s for zone: %s",
                    authentication.getPrincipal(), zoneId));
        }
    }

    protected FastTokenServices createFastTokenService(final List<String> trustedIssuers) {
        FastTokenServices tokenServices;
        tokenServices = this.fastRemoteTokenServicesCreator.newInstance();
        tokenServices.setStoreClaims(true);
        tokenServices.setUseHttps(this.useHttps);
        tokenServices.setTrustedIssuers(trustedIssuers);
        return tokenServices;
    }

    @Override
    public OAuth2AccessToken readAccessToken(final String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    public String getServiceId() {
        return this.serviceId;
    }

    @Required
    public void setServiceId(final String serviceId) {
        this.serviceId = serviceId;
    }

    public boolean isStoreClaims() {
        return this.storeClaims;
    }

    public void setStoreClaims(final boolean storeClaims) {
        this.storeClaims = storeClaims;
    }

    public boolean isUseHttps() {
        return this.useHttps;
    }

    public void setUseHttps(final boolean useHttps) {
        this.useHttps = useHttps;
    }

    public void setRequest(final HttpServletRequest request) {
        this.request = request;
    }

    public FastTokenServices getDefaultFastTokenService() {
        return this.defaultFastTokenService;
    }

    public void setDefaultFastTokenService(final FastTokenServices defaultFastTokenService) {
        this.defaultFastTokenService = defaultFastTokenService;
    }

    public void setFastRemoteTokenServicesCreator(final FastTokenServicesCreator fastRemoteTokenServicesCreator) {
        this.fastRemoteTokenServicesCreator = fastRemoteTokenServicesCreator;
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

    @Required
    public void setDefaultZoneConfig(final DefaultZoneConfiguration defaultZoneConfig) {
        this.defaultZoneConfig = defaultZoneConfig;
    }

    public List<String> getServiceZoneHeadersList() {
        return this.serviceZoneHeadersList;
    }

    public List<String> getServiceBaseDomainList() {
        return this.serviceBaseDomainList;
    }

}
