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

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.AntPathMatcher;

public class DefaultZoneConfiguration implements InitializingBean {
    private List<String> allowedUriPatterns;
    private List<String> trustedIssuerIds = new ArrayList<>();

    public DefaultZoneConfiguration(final List<String> allowedUriPatterns) {
        setAllowedUriPatterns(allowedUriPatterns);
    }

    // This field is for backward compatibility.
    public String getTrustedIssuerId() {
        return this.trustedIssuerIds.isEmpty() ? null : this.trustedIssuerIds.getFirst();
    }

    public void setTrustedIssuerId(final String trustedIssuerId) {
        this.trustedIssuerIds = new ArrayList<>(); // replace list
        if (null != trustedIssuerId) {
            this.trustedIssuerIds.add(trustedIssuerId);
        }
    }

    /**
     * A list of Ant-style path patterns as supported by {@linkplain AntPathMatcher}.
     *
     * @return
     */
    public List<String> getAllowedUriPatterns() {
        return this.allowedUriPatterns;
    }

    public void setAllowedUriPatterns(final List<String> allowedUriPatterns) {
        AntPathMatcher matcher = new AntPathMatcher();

        for (String pattern : allowedUriPatterns) {
            if (!matcher.isPattern(pattern)) {
                throw new IllegalArgumentException("Invalid pattern: " + pattern);
            }
        }
        this.allowedUriPatterns = allowedUriPatterns;
    }

    public List<String> getTrustedIssuerIds() {
        return this.trustedIssuerIds;
    }

    public void setTrustedIssuerIds(final List<String> trustedIssuerIds) {
        if (null == trustedIssuerIds) {
            this.trustedIssuerIds = new ArrayList<>();
        } else {
            this.trustedIssuerIds = new ArrayList<>(trustedIssuerIds);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (this.trustedIssuerIds == null || this.trustedIssuerIds.size() == 0) {
            throw new BeanCreationException("DefaultZoneConfiguration requires a default trusted Issuer");
        }
    }
}
