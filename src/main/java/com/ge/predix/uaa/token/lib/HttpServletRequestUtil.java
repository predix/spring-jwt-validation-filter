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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.StringUtils;

public final class HttpServletRequestUtil {

    private HttpServletRequestUtil() {
        // Prevents instantiation.
    }

    /**
     * @return empty string if requestHostname and baseDomain are identical, null if domain is not a sub-string of
     *         requestHostname
     */
    static String getZoneNameFromRequestHostName(final String requestHostname, final String baseDomain) {

        if (requestHostname.equals(baseDomain)) {
            return "";
        }
        String regexPattern = "^(.*?)\\." + Pattern.quote(baseDomain.toLowerCase()) + "$";
        Pattern pattern = Pattern.compile(regexPattern);

        Matcher matcher = pattern.matcher(requestHostname.toLowerCase());
        if (!matcher.matches()) {
            // There is no zone scope for this request. Return null
            return null;
        }

        String subdomain = matcher.group(1);

        return subdomain;
    }

    /**
     * Extract zone subdomain from request. If both subdomain and header are specificied, the zone subdomain in
     * servername overrides the header value.
     * 
     * @param headerNames
     */
    public static String getZoneName(final HttpServletRequest req, final List<String> serviceBaseDomainList,
            final List<String> headerNames, final boolean enableSubdomainsForZones) {
        String zoneName = null;

        if (enableSubdomainsForZones) {
            zoneName = getZoneFromSubdomain(req, serviceBaseDomainList);
        }

        if (StringUtils.isEmpty(zoneName)) {
            zoneName = findHeader(req, headerNames);
        }
        return zoneName;
    }

    private static String getZoneFromSubdomain(final HttpServletRequest req, final List<String> serviceBaseDomainList) {
        String zoneName = null;

        if (serviceBaseDomainList != null) {
            for (String serviceBaseDomain : serviceBaseDomainList) {
                zoneName = getZoneNameFromRequestHostName(req.getServerName(), serviceBaseDomain);
                if (zoneName != null) {
                    // If we have the zone name then break the loop
                    break;
                }
            }
        }
        return zoneName;
    }

    private static String findHeader(final HttpServletRequest req, final List<String> headerNames) {
        String subdomain;
        for (String name : headerNames) {
            subdomain = req.getHeader(name);
            if (!StringUtils.isEmpty(subdomain)) {
                return subdomain;
            }
        }

        return null;
    }
}
