package com.ge.predix.uaa.token.lib;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ZoneOAuth2AuthenticationTest {

    private static final String ZONE_ID = "test-zone-123";
    private static final String TOKEN_VALUE = "test.jwt.token";
    private Jwt mockJwt;
    private JwtAuthenticationToken mockJwtAuthToken;

    @BeforeMethod
    public void setUp() {
        // Create a mock JWT
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");
        headers.put("typ", "JWT");

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "test-user");
        claims.put("iss", "test-issuer");
        claims.put("aud", "test-audience");

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(3600);

        mockJwt = new Jwt(TOKEN_VALUE, issuedAt, expiresAt, headers, claims);

        // Create authorities
        Collection<GrantedAuthority> authorities = Arrays.asList(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")
        );

        // Create JwtAuthenticationToken
        mockJwtAuthToken = new JwtAuthenticationToken(mockJwt, authorities);
    }

    @Test
    public void testConstructor() {
        // Act
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Assert
        assertNotNull(auth);
        assertEquals(auth.getZoneId(), ZONE_ID);
    }

    @Test
    public void testConstructorWithNullZoneId() {
        // Act
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, null);

        // Assert
        assertNotNull(auth);
        assertNull(auth.getZoneId());
    }

    @Test
    public void testConstructorWithEmptyZoneId() {
        // Act
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, "");

        // Assert
        assertNotNull(auth);
        assertEquals(auth.getZoneId(), "");
    }

    @Test
    public void testGetZoneId() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        String zoneId = auth.getZoneId();

        // Assert
        assertEquals(zoneId, ZONE_ID);
    }

    @Test
    public void testGetZoneIdWithDifferentValues() {
        // Test with different zone IDs
        String zoneId1 = "zone-1";
        String zoneId2 = "zone-2";
        String zoneId3 = "production-zone";

        ZoneOAuth2Authentication auth1 = new ZoneOAuth2Authentication(mockJwtAuthToken, zoneId1);
        ZoneOAuth2Authentication auth2 = new ZoneOAuth2Authentication(mockJwtAuthToken, zoneId2);
        ZoneOAuth2Authentication auth3 = new ZoneOAuth2Authentication(mockJwtAuthToken, zoneId3);

        assertEquals(auth1.getZoneId(), zoneId1);
        assertEquals(auth2.getZoneId(), zoneId2);
        assertEquals(auth3.getZoneId(), zoneId3);
    }

    @Test
    public void testToString() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        String result = auth.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("ZoneOAuth2Authentication"));
        assertTrue(result.contains("zoneId"));
        assertTrue(result.contains(ZONE_ID));
        assertEquals(result, "ZoneOAuth2Authentication [zoneId=" + ZONE_ID + "]");
    }

    @Test
    public void testToStringWithNullZoneId() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, null);

        // Act
        String result = auth.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("ZoneOAuth2Authentication"));
        assertTrue(result.contains("null"));
        assertEquals(result, "ZoneOAuth2Authentication [zoneId=null]");
    }

    @Test
    public void testToStringWithEmptyZoneId() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, "");

        // Act
        String result = auth.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("ZoneOAuth2Authentication"));
        assertEquals(result, "ZoneOAuth2Authentication [zoneId=]");
    }

    @Test
    public void testInheritedGetToken() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        Jwt token = auth.getToken();

        // Assert
        assertNotNull(token);
        assertSame(token, mockJwt);
        assertEquals(token.getTokenValue(), TOKEN_VALUE);
    }

    @Test
    public void testInheritedGetAuthorities() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        Collection<GrantedAuthority> authorities = auth.getAuthorities();

        // Assert
        assertNotNull(authorities);
        assertEquals(authorities.size(), 2);
        assertTrue(authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        assertTrue(authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    public void testInheritedGetAuthoritiesWithEmptyAuthorities() {
        // Arrange
        JwtAuthenticationToken emptyAuthToken = new JwtAuthenticationToken(mockJwt, Collections.emptyList());
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(emptyAuthToken, ZONE_ID);

        // Act
        Collection<GrantedAuthority> authorities = auth.getAuthorities();

        // Assert
        assertNotNull(authorities);
        assertEquals(authorities.size(), 0);
    }

    @Test
    public void testInheritedGetAuthoritiesWithSingleAuthority() {
        // Arrange
        Collection<GrantedAuthority> singleAuthority = Collections.singleton(
                new SimpleGrantedAuthority("ROLE_USER")
        );
        JwtAuthenticationToken singleAuthToken = new JwtAuthenticationToken(mockJwt, singleAuthority);
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(singleAuthToken, ZONE_ID);

        // Act
        Collection<GrantedAuthority> authorities = auth.getAuthorities();

        // Assert
        assertNotNull(authorities);
        assertEquals(authorities.size(), 1);
        assertTrue(authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    public void testSerialVersionUID() {
        // This test ensures the class can be instantiated and is properly defined
        // The serialVersionUID field is used for serialization compatibility
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Verify the object is created successfully
        assertNotNull(auth);
        assertNotNull(auth.getZoneId());
    }

    @Test
    public void testMultipleInstancesWithDifferentZones() {
        // Create multiple instances
        ZoneOAuth2Authentication auth1 = new ZoneOAuth2Authentication(mockJwtAuthToken, "zone-1");
        ZoneOAuth2Authentication auth2 = new ZoneOAuth2Authentication(mockJwtAuthToken, "zone-2");
        ZoneOAuth2Authentication auth3 = new ZoneOAuth2Authentication(mockJwtAuthToken, "zone-3");

        // Verify each has its own zone ID
        assertEquals(auth1.getZoneId(), "zone-1");
        assertEquals(auth2.getZoneId(), "zone-2");
        assertEquals(auth3.getZoneId(), "zone-3");

        // Verify all share the same token
        assertSame(auth1.getToken(), auth2.getToken());
        assertSame(auth2.getToken(), auth3.getToken());
    }

    @Test
    public void testGetName() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        String name = auth.getName();

        // Assert - getName() should return the subject from the JWT
        assertNotNull(name);
        assertEquals(name, "test-user");
    }

    @Test
    public void testGetTokenAttributes() {
        // Arrange
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, ZONE_ID);

        // Act
        Map<String, Object> tokenAttributes = auth.getTokenAttributes();

        // Assert
        assertNotNull(tokenAttributes);
        assertEquals(tokenAttributes.get("sub"), "test-user");
        assertEquals(tokenAttributes.get("iss"), "test-issuer");
        assertEquals(tokenAttributes.get("aud"), "test-audience");
    }

    @Test
    public void testCompleteWorkflow() {
        // Create a complete workflow test
        String zoneId = "production-zone-456";

        // Create JWT with specific claims
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user@example.com");
        claims.put("iss", "https://uaa.example.com");
        claims.put("scope", Arrays.asList("read", "write"));

        Jwt jwt = new Jwt(
                "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                headers,
                claims
        );

        Collection<GrantedAuthority> authorities = Arrays.asList(
                new SimpleGrantedAuthority("scope_read"),
                new SimpleGrantedAuthority("scope_write")
        );

        JwtAuthenticationToken jwtAuth = new JwtAuthenticationToken(jwt, authorities);
        ZoneOAuth2Authentication zoneAuth = new ZoneOAuth2Authentication(jwtAuth, zoneId);

        // Verify all aspects
        assertEquals(zoneAuth.getZoneId(), zoneId);
        assertEquals(zoneAuth.getName(), "user@example.com");
        assertEquals(zoneAuth.getAuthorities().size(), 2);
        assertNotNull(zoneAuth.getToken());
        assertTrue(zoneAuth.toString().contains(zoneId));
    }

    @Test
    public void testZoneIdImmutability() {
        // Arrange
        String originalZoneId = "immutable-zone";
        ZoneOAuth2Authentication auth = new ZoneOAuth2Authentication(mockJwtAuthToken, originalZoneId);

        // Act - get zone ID multiple times
        String zoneId1 = auth.getZoneId();
        String zoneId2 = auth.getZoneId();
        String zoneId3 = auth.getZoneId();

        // Assert - zone ID should remain the same (it's final)
        assertEquals(zoneId1, originalZoneId);
        assertEquals(zoneId2, originalZoneId);
        assertEquals(zoneId3, originalZoneId);
        assertSame(zoneId1, zoneId2);
    }
}

