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

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestClient;

/**
 * Service for handling Zac tokens.
 */
public class ZacTokenService extends AbstractZoneAwareTokenService implements InitializingBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZacTokenService.class);

    private LoadingCache<String, FastTokenServices> tokenServicesCache;

    private final ClientRegistration clientRegistration;

    private final String zacUrl;

    @Value("${ISSUERS_TTL_SECONDS:86400}")
    private long issuersTtlSeconds;

    /**
     * Sample Client registration snippet.
     * ClientRegistration.withRegistrationId("zacUaaClientDetails")
     * .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
     * .clientId(uaaAdminClientId)
     * .clientSecret(uaaAdminClientSecret)
     * .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
     * .tokenUri(uaaTokenUri)
     * .build()
     */
    public ZacTokenService(final String serviceId, final DefaultZoneConfiguration defaultZoneConfig,
                           final String zacUrl, final HttpServletRequest request,
                           final ClientRegistration clientRegistration) {
        super(serviceId, defaultZoneConfig, request);
        this.zacUrl = zacUrl;
        this.clientRegistration = clientRegistration;
    }

    /**
     * Retrieves or creates a FastTokenServices instance for the given zone ID.
     *
     * @param zoneId the zone ID
     * @return the FastTokenServices instance
     */
    @Override
    protected FastTokenServices getOrCreateZoneTokenService(final String zoneId) {
        return this.tokenServicesCache.get(zoneId);
    }

    /**
     * Creates a FastTokenServices instance for the given zone ID.
     *
     * @param zoneId the zone ID
     * @return the FastTokenServices instance
     */
    protected FastTokenServices createFastTokenService(final String zoneId) {
        LOGGER.debug("Creating FastTokenServices for zone: {}", zoneId);
        FastTokenServices tokenServices;
        String trustedIssuersURL = this.zacUrl + "/v1/registration/" + getServiceId() + "/" + zoneId;
        try {
            OAuth2ClientHttpRequestInterceptor interceptor = getOAuth2ClientHttpRequestInterceptor();
            ResponseEntity<TrustedIssuers> response = RestClient.builder()
                                                                .requestInterceptor(interceptor)
                                                                .defaultStatusHandler(new DefaultResponseErrorHandler())
                                                                .build().get().uri(trustedIssuersURL).retrieve()
                                                                .toEntity(TrustedIssuers.class);
            tokenServices = super.createFastTokenService(
                Objects.requireNonNull(response.getBody()).getTrustedIssuerIds());
        } catch (Exception e) {
            LOGGER.error("Failed to get trusted issuers from: {}", trustedIssuersURL, e);
            throw e;
        }
        LOGGER.debug("Created FastTokenServices for zone: {}", zoneId);
        return tokenServices;
    }

    /**
     * Creates an OAuth2ClientHttpRequestInterceptor for the client registration.
     *
     * @return the OAuth2ClientHttpRequestInterceptor instance
     */
    private OAuth2ClientHttpRequestInterceptor getOAuth2ClientHttpRequestInterceptor() {
        var clientRegistrationRepository = new InMemoryClientRegistrationRepository(clientRegistration);
        var clientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
        var authorizedClientManager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, clientService);
        var interceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        interceptor.setClientRegistrationIdResolver(request -> clientRegistration.getRegistrationId());
        return interceptor;
    }

    public void setIssuersTtlSeconds(final long issuersTtlSeconds) {
        this.issuersTtlSeconds = issuersTtlSeconds;
    }

    private void checkIfZonePropertiesSet() {
        if (CollectionUtils.isEmpty(this.getServiceBaseDomainList())
                && CollectionUtils.isEmpty(this.getServiceZoneHeadersList())) {
            throw new IllegalStateException("ZacTokenService requires at least one of the following properties to be"
                    + "configured: serviceBaseDomain or serviceZoneHeaders .");
        }
    }

    @Override
    public void afterPropertiesSet() {
        LOGGER.info("TTL for token services cache is set to {} seconds.", this.issuersTtlSeconds);
        this.tokenServicesCache = Caffeine.newBuilder().expireAfterWrite(this.issuersTtlSeconds, TimeUnit.SECONDS)
                .build(this::createFastTokenService);
        checkIfZonePropertiesSet();
    }
}
