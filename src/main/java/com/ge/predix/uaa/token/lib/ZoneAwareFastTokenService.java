package com.ge.predix.uaa.token.lib;

public class ZoneAwareFastTokenService extends AbstractZoneAwareTokenService {

    protected FastTokenServices getOrCeateZoneTokenService(final String zoneId) {
        return getDefaultFastTokenService();
    }
}
