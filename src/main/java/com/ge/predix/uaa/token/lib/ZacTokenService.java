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
