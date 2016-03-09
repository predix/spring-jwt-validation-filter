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
