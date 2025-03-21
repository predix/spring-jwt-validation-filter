package com.ge.predix.uaa.token.lib;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource
    .OAuth2ResourceServerConfigurer;

public class ZacTokenServiceCustomizer implements
                                         Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer> {

    private final ZacTokenService zacTokenService;

    public ZacTokenServiceCustomizer(final ZacTokenService zacTokenService) {
        this.zacTokenService = zacTokenService;
    }

    @Override
    public void customize(final OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
        ProviderManager providerManager = new ProviderManager(this.zacTokenService);
        jwtConfigurer.authenticationManager(providerManager);
    }
}