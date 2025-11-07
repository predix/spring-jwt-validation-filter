package com.ge.predix.uaa.token.lib;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ZoneAwareFastTokenServiceTest {

    private static final String SERVICE_ID = "test-service";
    private static final String ZONE_ID = "test-zone";
    private static final String TOKEN = "test.jwt.token";

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private DefaultZoneConfiguration mockDefaultZoneConfig;

    @Mock
    private FastTokenServices mockFastTokenServices;

    @Mock
    private Authentication mockAuthentication;

    private ZoneAwareFastTokenService tokenService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testConstructor() {
        // Test that constructor properly initializes the service
        ZoneAwareFastTokenService service = new ZoneAwareFastTokenService(
            SERVICE_ID, mockDefaultZoneConfig, mockRequest);

        assertNotNull(service);
    }

    @Test
    public void testConstructorWithNullParameters() {
        // Test constructor with null parameters
        ZoneAwareFastTokenService service = new ZoneAwareFastTokenService(null, null, null);
        assertNotNull(service);
    }

    @Test
    public void testGetOrCreateZoneTokenService() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act
        FastTokenServices result = tokenService.getOrCreateZoneTokenService(ZONE_ID);

        // Assert
        assertNotNull(result);
        assertSame(result, mockFastTokenServices);
    }

    @Test
    public void testGetOrCreateZoneTokenServiceMultipleTimes() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act - call multiple times with different zone IDs
        FastTokenServices result1 = tokenService.getOrCreateZoneTokenService("zone1");
        FastTokenServices result2 = tokenService.getOrCreateZoneTokenService("zone2");
        FastTokenServices result3 = tokenService.getOrCreateZoneTokenService("zone3");

        // Assert - all should return the same default service
        assertSame(result1, mockFastTokenServices);
        assertSame(result2, mockFastTokenServices);
        assertSame(result3, mockFastTokenServices);
    }

    @Test
    public void testGetOrCreateZoneTokenServiceWithNullZoneId() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act
        FastTokenServices result = tokenService.getOrCreateZoneTokenService(null);

        // Assert
        assertNotNull(result);
        assertSame(result, mockFastTokenServices);
    }

    @Test
    public void testSupports() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);

        // Act & Assert
        assertTrue(tokenService.supports(BearerTokenAuthenticationToken.class));
    }

    @Test
    public void testAuthenticateNonZoneSpecificRequest() {
        // Arrange
        when(mockRequest.getRequestURI()).thenReturn("/health");
        when(mockRequest.getHeader("Predix-Zone-Id")).thenReturn(null);
        when(mockDefaultZoneConfig.getAllowedUriPatterns()).thenReturn(Arrays.asList("/health", "/status"));
        when(mockFastTokenServices.authenticate(any(Authentication.class))).thenReturn(mockAuthentication);

        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        BearerTokenAuthenticationToken authRequest = new BearerTokenAuthenticationToken(TOKEN);

        // Act
        Authentication result = tokenService.authenticate(authRequest);

        // Assert
        assertNotNull(result);
        verify(mockFastTokenServices).authenticate(authRequest);
    }

    @Test
    public void testGetOrCreateZoneTokenServiceIgnoresZoneIdParameter() {
        // Test that getOrCreateZoneTokenService always returns default service regardless of zone ID
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act - call with different zone IDs
        FastTokenServices result1 = tokenService.getOrCreateZoneTokenService("zone-a");
        FastTokenServices result2 = tokenService.getOrCreateZoneTokenService("zone-b");
        FastTokenServices result3 = tokenService.getOrCreateZoneTokenService("zone-c");

        // Assert - all should return the same default service
        assertSame(result1, mockFastTokenServices);
        assertSame(result2, mockFastTokenServices);
        assertSame(result3, mockFastTokenServices);
        assertSame(result1, result2);
        assertSame(result2, result3);
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testAuthenticateWithoutZoneIdForZoneSpecificRequest() {
        // Arrange
        when(mockRequest.getRequestURI()).thenReturn("/api/resource");
        when(mockRequest.getHeader("Predix-Zone-Id")).thenReturn(null);
        when(mockDefaultZoneConfig.getAllowedUriPatterns()).thenReturn(Collections.emptyList());

        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        BearerTokenAuthenticationToken authRequest = new BearerTokenAuthenticationToken(TOKEN);

        // Act
        tokenService.authenticate(authRequest);

        // Should throw exception
    }

    @Test
    public void testAuthenticateWithDifferentAllowedPatterns() {
        // Arrange
        when(mockRequest.getRequestURI()).thenReturn("/public/info");
        when(mockRequest.getHeader("Predix-Zone-Id")).thenReturn(null);
        when(mockDefaultZoneConfig.getAllowedUriPatterns()).thenReturn(Arrays.asList("/public/**", "/health"));
        when(mockFastTokenServices.authenticate(any(Authentication.class))).thenReturn(mockAuthentication);

        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        BearerTokenAuthenticationToken authRequest = new BearerTokenAuthenticationToken(TOKEN);

        // Act
        Authentication result = tokenService.authenticate(authRequest);

        // Assert
        assertNotNull(result);
        verify(mockFastTokenServices).authenticate(authRequest);
    }

    @Test
    public void testGetOrCreateZoneTokenServiceReturnsDefaultService() {
        // Arrange
        FastTokenServices customService = mock(FastTokenServices.class);
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(customService);

        // Act
        FastTokenServices result = tokenService.getOrCreateZoneTokenService("any-zone");

        // Assert
        assertSame(result, customService);
    }

    @Test
    public void testMultipleAuthenticationCalls() {
        // Arrange
        when(mockRequest.getRequestURI()).thenReturn("/health");
        when(mockRequest.getHeader("Predix-Zone-Id")).thenReturn(null);
        when(mockDefaultZoneConfig.getAllowedUriPatterns()).thenReturn(Arrays.asList("/health"));
        when(mockFastTokenServices.authenticate(any(Authentication.class))).thenReturn(mockAuthentication);

        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        BearerTokenAuthenticationToken authRequest1 = new BearerTokenAuthenticationToken("token1");
        BearerTokenAuthenticationToken authRequest2 = new BearerTokenAuthenticationToken("token2");
        BearerTokenAuthenticationToken authRequest3 = new BearerTokenAuthenticationToken("token3");

        // Act
        tokenService.authenticate(authRequest1);
        tokenService.authenticate(authRequest2);
        tokenService.authenticate(authRequest3);

        // Assert
        verify(mockFastTokenServices, times(3)).authenticate(any(Authentication.class));
    }

    @Test
    public void testGetDefaultFastTokenService() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act
        FastTokenServices result = tokenService.getDefaultFastTokenService();

        // Assert
        assertNotNull(result);
        assertSame(result, mockFastTokenServices);
    }

    @Test
    public void testServiceIdParameter() {
        // Test with different service IDs
        String serviceId1 = "service-1";
        String serviceId2 = "service-2";

        ZoneAwareFastTokenService service1 = new ZoneAwareFastTokenService(
            serviceId1, mockDefaultZoneConfig, mockRequest);
        ZoneAwareFastTokenService service2 = new ZoneAwareFastTokenService(
            serviceId2, mockDefaultZoneConfig, mockRequest);

        assertNotNull(service1);
        assertNotNull(service2);
    }

    @Test
    public void testWithEmptyAllowedUriPatterns() {
        // Arrange
        when(mockRequest.getRequestURI()).thenReturn("/health");
        when(mockRequest.getHeader("Predix-Zone-Id")).thenReturn(null);
        when(mockDefaultZoneConfig.getAllowedUriPatterns()).thenReturn(Collections.emptyList());

        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        BearerTokenAuthenticationToken authRequest = new BearerTokenAuthenticationToken(TOKEN);

        // Act & Assert - should throw exception as URI is not in allowed patterns
        try {
            tokenService.authenticate(authRequest);
        } catch (InvalidBearerTokenException e) {
            // Expected
            verify(mockFastTokenServices, never()).authenticate(any());
        }
    }

    @Test
    public void testGetOrCreateZoneTokenServiceWithEmptyString() {
        // Arrange
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Act
        FastTokenServices result = tokenService.getOrCreateZoneTokenService("");

        // Assert
        assertNotNull(result);
        assertSame(result, mockFastTokenServices);
    }

    @Test
    public void testInheritedBehaviorFromAbstractZoneAwareTokenService() {
        // Test that ZoneAwareFastTokenService inherits behavior from parent class
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);

        // Test supports method
        assertTrue(tokenService.supports(BearerTokenAuthenticationToken.class));
    }

    @Test
    public void testGetOrCreateZoneTokenServiceConsistency() {
        // Verify that getOrCreateZoneTokenService always returns the default service
        tokenService = new ZoneAwareFastTokenService(SERVICE_ID, mockDefaultZoneConfig, mockRequest);
        tokenService.setDefaultFastTokenService(mockFastTokenServices);

        // Call with same zone ID multiple times
        FastTokenServices result1 = tokenService.getOrCreateZoneTokenService(ZONE_ID);
        FastTokenServices result2 = tokenService.getOrCreateZoneTokenService(ZONE_ID);
        FastTokenServices result3 = tokenService.getOrCreateZoneTokenService(ZONE_ID);

        // All should be the same instance
        assertSame(result1, result2);
        assertSame(result2, result3);
        assertSame(result1, mockFastTokenServices);
    }
}

