package com.ge.predix.uaa.token.lib;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.server.ResponseStatusException;
import org.testng.annotations.Test;

public class AbstractZoneAwareTokenServiceTest {

    @Test
    public void authenticate_ValidNonZoneSpecificRequest_ReturnsAuthentication() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/non-zone-specific");
        when(request.getHeader("Predix-Zone-Id")).thenReturn(null);

        DefaultZoneConfiguration defaultZoneConfig = mock(DefaultZoneConfiguration.class);
        when(defaultZoneConfig.getAllowedUriPatterns()).thenReturn(List.of("/non-zone-specific"));

        AbstractZoneAwareTokenService tokenService = new AbstractZoneAwareTokenService("serviceId", defaultZoneConfig, request) {
            @Override
            protected FastTokenServices getOrCreateZoneTokenService(String zoneId) {
                return null;
            }
        };

        Authentication authentication = mock(Authentication.class);
        FastTokenServices fastTokenServices = mock(FastTokenServices.class);
        when(fastTokenServices.authenticate(authentication)).thenReturn(authentication);
        tokenService.setDefaultFastTokenService(fastTokenServices);

        Authentication result = tokenService.authenticate(authentication);
        assertNotNull(result);
        assertEquals(result, authentication);
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void authenticate_InvalidZoneSpecificRequest_ThrowsException() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/zone-specific");
        when(request.getHeader("Predix-Zone-Id")).thenReturn(null);

        DefaultZoneConfiguration defaultZoneConfig = mock(DefaultZoneConfiguration.class);
        when(defaultZoneConfig.getAllowedUriPatterns()).thenReturn(List.of("/non-zone-specific"));

        AbstractZoneAwareTokenService tokenService = new AbstractZoneAwareTokenService("serviceId", defaultZoneConfig, request) {
            @Override
            protected FastTokenServices getOrCreateZoneTokenService(String zoneId) {
                return null;
            }
        };
        Authentication authentication = mock(Authentication.class);
        tokenService.authenticate(authentication);
    }

    @Test
    public void normalizeUri_ValidUri_ReturnsNormalizedUri() {
        AbstractZoneAwareTokenService tokenService = new AbstractZoneAwareTokenService("serviceId", null, null) {
            @Override
            protected FastTokenServices getOrCreateZoneTokenService(String zoneId) {
                return null;
            }
        };

        String requestUri = "/v1/hello/../policy-set/my%20policy";
        String expectedUri = "/v1/policy-set/my%20policy";
        String result = tokenService.normalizeUri(requestUri);
        assertEquals(expectedUri, result);
    }

    @Test(expectedExceptions = ResponseStatusException.class)
    public void normalizeUri_InvalidUri_ThrowsException() {
        AbstractZoneAwareTokenService tokenService = new AbstractZoneAwareTokenService("serviceId", null, null) {
            @Override
            protected FastTokenServices getOrCreateZoneTokenService(String zoneId) {
                return null;
            }
        };

        String requestUri = "https://";
        tokenService.normalizeUri(requestUri);
    }

}
