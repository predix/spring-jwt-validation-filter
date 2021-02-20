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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * Authentication object to hold currently authorized zone.
 *
 * @author 212319607
 */
public class ZoneOAuth2Authentication extends OAuth2Authentication {

    private static final long serialVersionUID = 1L;

    private final String zoneId;

    public ZoneOAuth2Authentication(final OAuth2Request storedRequest, final Authentication userAuthentication,
            final String zoneId) {
        super(storedRequest, userAuthentication);
        this.zoneId = zoneId;
    }

    public String getZoneId() {
        return this.zoneId;
    }

    @Override
    public String toString() {
        return "ZoneOAuth2Authentication [zoneId=" + this.zoneId + "]";
    }

}
