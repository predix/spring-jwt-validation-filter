package com.ge.predix.uaa.token.lib;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNotSame;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ZacTokenServiceCustomizerTest {

    @Mock
    private ZacTokenService mockZacTokenService;

    @Mock
    private OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer mockJwtConfigurer;

    private ZacTokenServiceCustomizer customizer;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        customizer = new ZacTokenServiceCustomizer(mockZacTokenService);
    }

    @Test
    public void testConstructor() {
        // Test that the constructor properly initializes the customizer
        ZacTokenServiceCustomizer newCustomizer = new ZacTokenServiceCustomizer(mockZacTokenService);
        assertNotNull(newCustomizer);
    }

    @Test
    public void testConstructorWithNullService() {
        // Test constructor with null ZacTokenService
        ZacTokenServiceCustomizer customizerWithNull = new ZacTokenServiceCustomizer(null);
        assertNotNull(customizerWithNull);
    }

    @Test
    public void testCustomize() {
        // Arrange
        ArgumentCaptor<AuthenticationManager> authManagerCaptor = ArgumentCaptor.forClass(AuthenticationManager.class);
        when(mockJwtConfigurer.authenticationManager(any(AuthenticationManager.class)))
                .thenReturn(mockJwtConfigurer);

        // Act
        customizer.customize(mockJwtConfigurer);

        // Assert
        verify(mockJwtConfigurer).authenticationManager(authManagerCaptor.capture());
        
        AuthenticationManager capturedAuthManager = authManagerCaptor.getValue();
        assertNotNull(capturedAuthManager);
        assertEquals(capturedAuthManager.getClass(), ProviderManager.class);
    }

    @Test
    public void testCustomizeWithProviderManager() {
        // Arrange
        ArgumentCaptor<ProviderManager> providerManagerCaptor = ArgumentCaptor.forClass(ProviderManager.class);
        when(mockJwtConfigurer.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer);

        // Act
        customizer.customize(mockJwtConfigurer);

        // Assert
        verify(mockJwtConfigurer).authenticationManager(providerManagerCaptor.capture());
        
        ProviderManager capturedProviderManager = providerManagerCaptor.getValue();
        assertNotNull(capturedProviderManager);
        
        // Verify that the provider manager contains our ZacTokenService
        assertNotNull(capturedProviderManager.getProviders());
        assertEquals(capturedProviderManager.getProviders().size(), 1);
        assertEquals(capturedProviderManager.getProviders().get(0), mockZacTokenService);
    }

    @Test
    public void testCustomizeCreatesNewProviderManagerEachTime() {
        // Arrange
        ArgumentCaptor<ProviderManager> providerManagerCaptor1 = ArgumentCaptor.forClass(ProviderManager.class);
        ArgumentCaptor<ProviderManager> providerManagerCaptor2 = ArgumentCaptor.forClass(ProviderManager.class);
        
        OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer mockJwtConfigurer2 = 
            mock(OAuth2ResourceServerConfigurer.JwtConfigurer.class);
        
        when(mockJwtConfigurer.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer);
        when(mockJwtConfigurer2.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer2);

        // Act - call customize twice
        customizer.customize(mockJwtConfigurer);
        customizer.customize(mockJwtConfigurer2);

        // Assert - verify both calls created provider managers
        verify(mockJwtConfigurer).authenticationManager(providerManagerCaptor1.capture());
        verify(mockJwtConfigurer2).authenticationManager(providerManagerCaptor2.capture());
        
        ProviderManager pm1 = providerManagerCaptor1.getValue();
        ProviderManager pm2 = providerManagerCaptor2.getValue();
        
        assertNotNull(pm1);
        assertNotNull(pm2);
        assertNotSame(pm1, pm2); // Different instances
        
        // Both should contain the same ZacTokenService
        assertEquals(pm1.getProviders().get(0), mockZacTokenService);
        assertEquals(pm2.getProviders().get(0), mockZacTokenService);
    }

    @Test
    public void testMultipleZacTokenServiceCustomizers() {
        // Arrange
        ZacTokenService mockZacTokenService2 = mock(ZacTokenService.class);
        ZacTokenServiceCustomizer customizer2 = new ZacTokenServiceCustomizer(mockZacTokenService2);
        
        ArgumentCaptor<ProviderManager> providerManagerCaptor1 = ArgumentCaptor.forClass(ProviderManager.class);
        ArgumentCaptor<ProviderManager> providerManagerCaptor2 = ArgumentCaptor.forClass(ProviderManager.class);
        
        OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer mockJwtConfigurer2 = 
            mock(OAuth2ResourceServerConfigurer.JwtConfigurer.class);
        
        when(mockJwtConfigurer.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer);
        when(mockJwtConfigurer2.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer2);

        // Act
        customizer.customize(mockJwtConfigurer);
        customizer2.customize(mockJwtConfigurer2);

        // Assert
        verify(mockJwtConfigurer).authenticationManager(providerManagerCaptor1.capture());
        verify(mockJwtConfigurer2).authenticationManager(providerManagerCaptor2.capture());
        
        ProviderManager pm1 = providerManagerCaptor1.getValue();
        ProviderManager pm2 = providerManagerCaptor2.getValue();
        
        assertNotNull(pm1);
        assertNotNull(pm2);
        
        // Each customizer should have its own ZacTokenService
        assertEquals(pm1.getProviders().get(0), mockZacTokenService);
        assertEquals(pm2.getProviders().get(0), mockZacTokenService2);
    }


    @Test
    public void testCustomizeMultipleTimes() {
        // Arrange
        ArgumentCaptor<ProviderManager> providerManagerCaptor = ArgumentCaptor.forClass(ProviderManager.class);
        when(mockJwtConfigurer.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer);

        // Act - call customize multiple times with the same configurer
        customizer.customize(mockJwtConfigurer);
        customizer.customize(mockJwtConfigurer);
        customizer.customize(mockJwtConfigurer);

        // Assert - verify it was called 3 times
        verify(mockJwtConfigurer, org.mockito.Mockito.times(3))
            .authenticationManager(any(ProviderManager.class));
    }

    @Test
    public void testProviderManagerContainsCorrectProvider() {
        // Arrange
        ArgumentCaptor<ProviderManager> providerManagerCaptor = ArgumentCaptor.forClass(ProviderManager.class);
        when(mockJwtConfigurer.authenticationManager(any(ProviderManager.class)))
                .thenReturn(mockJwtConfigurer);

        // Act
        customizer.customize(mockJwtConfigurer);

        // Assert
        verify(mockJwtConfigurer).authenticationManager(providerManagerCaptor.capture());
        
        ProviderManager capturedProviderManager = providerManagerCaptor.getValue();
        
        // Verify only one provider
        assertEquals(capturedProviderManager.getProviders().size(), 1);
        
        // Verify it's the correct ZacTokenService instance
        assertEquals(capturedProviderManager.getProviders().get(0), mockZacTokenService);
    }
}

