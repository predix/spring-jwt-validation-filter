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

import java.util.List;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.util.AntPathMatcher;

public class DefaultZoneConfiguration {
    private String trustedIssuerId;
    private List<String> allowedUriPatterns;

    public String getTrustedIssuerId() {
        return this.trustedIssuerId;
    }

    @Required
    public void setTrustedIssuerId(final String trustedIssuerId) {
        this.trustedIssuerId = trustedIssuerId;
    }

    /**
     * A list of Ant-style path patterns as supported by {@linkplain AntPathMatcher}.
     *
     * @return
     */
    public List<String> getAllowedUriPatterns() {
        return this.allowedUriPatterns;
    }

    @Required
    public void setAllowedUriPatterns(final List<String> allowedUriPatterns) {
        AntPathMatcher matcher = new AntPathMatcher();

        for (String pattern : allowedUriPatterns) {
            if (!matcher.isPattern(pattern)) {
                throw new IllegalArgumentException("Invalid pattern: " + pattern);
            }
        }
        this.allowedUriPatterns = allowedUriPatterns;
    }

}
