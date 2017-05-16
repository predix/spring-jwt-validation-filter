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

import java.util.Map;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.map.PassiveExpiringMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

/**
 *
 * @author 212304931
 */
public class ZacTokenService extends AbstractZoneAwareTokenService implements InitializingBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZacTokenService.class);

    private Map<String, FastTokenServices> tokenServicesMap;

    private RestOperations oauth2RestTemplate;

    private String zacUrl;

    @Value("${ISSUERS_TTL_SECONDS:86400}")
    private long issuersTtlSeconds;

    @Override
    protected FastTokenServices getOrCreateZoneTokenService(final String zoneId) {
        FastTokenServices tokenServices;
        tokenServices = this.tokenServicesMap.get(zoneId);
        String trustedIssuersURL = this.zacUrl + "/v1/registration/" + getServiceId() + "/" + zoneId;
        if (null == tokenServices) {
            try {
                final ResponseEntity<TrustedIssuers> responseEntity = this.oauth2RestTemplate
                        .getForEntity(trustedIssuersURL, TrustedIssuers.class);
                tokenServices = createFastTokenService(responseEntity.getBody().getTrustedIssuerIds());
                this.tokenServicesMap.put(zoneId, tokenServices);
            } catch (Exception e) {
                LOGGER.error("Failed to get trusted issuers from: " + trustedIssuersURL);
                LOGGER.error(e.getMessage());
                throw e;
            }

        }
        return tokenServices;
    }

    public Map<String, FastTokenServices> getTokenServicesMap() {
        return this.tokenServicesMap;
    }

    public void setOauth2RestTemplate(final RestOperations oauth2RestTemplate) {
        this.oauth2RestTemplate = oauth2RestTemplate;
    }

    @Required
    public void setZacUrl(final String zacUrl) {
        this.zacUrl = zacUrl;
    }

    public void setIssuersTtlSeconds(final long issuersTtlSeconds) {
        this.issuersTtlSeconds = issuersTtlSeconds;
    }

    public void flushIssuerCache(final String zoneId) {
        this.tokenServicesMap.remove(zoneId);
    }

    private void checkIfZonePropertiesSet() {
        if (CollectionUtils.isEmpty(this.getServiceBaseDomainList())
                && CollectionUtils.isEmpty(this.getServiceZoneHeadersList())) {
            throw new IllegalStateException("ZacTokenService requires atleast one of the following properties to be"
                    + "configured: serviceBaseDomain or serviceZoneHeaders .");
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        long timeToLiveMillis = this.issuersTtlSeconds * 1000;
        this.tokenServicesMap = new PassiveExpiringMap<>(timeToLiveMillis);
        checkIfZonePropertiesSet();
    }
}
