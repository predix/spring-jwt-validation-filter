package com.ge.predix.uaa.token.lib;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource
    .OAuth2ResourceServerConfigurer;

public class FastTokenServiceCustomizer implements
                                         Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer> {

    private final FastTokenServices fastTokenServices;

    public FastTokenServiceCustomizer(final FastTokenServices fastTokenServices) {
        this.fastTokenServices = fastTokenServices;
    }

    @Override
    public void customize(final OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
        ProviderManager providerManager = new ProviderManager(this.fastTokenServices);
        jwtConfigurer.authenticationManager(providerManager);
    }
}