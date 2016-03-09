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

        String regexPattern = "^(.*?)\\." + Pattern.quote(baseDomain) + "$";
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(requestHostname);
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
    public static String getZoneName(final HttpServletRequest req, final String serviceBaseDomain,
            List<String> headerNames) {
        String zoneName = null;
        
        if (!StringUtils.isEmpty(serviceBaseDomain)) {
            zoneName = getZoneNameFromRequestHostName(req.getServerName(), serviceBaseDomain);
        }
        

        if (StringUtils.isEmpty(zoneName)) {
           zoneName = findHeader(req, headerNames);
        }
        return zoneName;
    }


    private static String findHeader(final HttpServletRequest req, final List<String>headerNames) {
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
