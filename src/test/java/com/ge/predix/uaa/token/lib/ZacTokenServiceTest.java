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

import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestTemplate;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class ZacTokenServiceTest {

    private static final String PREDIX_ZONE_HEADER_NAME = "Predix-Zone-Id";
    private final TestTokenUtil tokenUtil = new TestTokenUtil();
    private static final String ZONE = "testzone1";
    private static final String BASE_DOMAIN = "localhost";
    private static final String SERVICEID = "acs";
    private static final String DEFAULT_TRUSTED_ISSUER = "https://issuer.com/oauth/token";
    private static final List<String> ZONE_TRUSTED_ISSUERS = Arrays.asList("http://myuaa.com",
            "http://localhost:8080/uaa/oauth/token");

    public void testLoadAuthentication() {
        // testing when zone id is not null
        String zoneUserScope = SERVICEID + ".zones." + ZONE + ".user";
        assertAuthentication(loadAuthentication(ZONE, zoneUserScope), ZONE);
    }

    public void testLoadAuthenticationWhenZoneIdisNull() {
        // testing when zone is null, for a non-zone specific request
        assertAuthentication(loadAuthentication(null, "some-other-scope", "/zone/a", Arrays.asList("/zone/**")), null);
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationUnauthorizedScope() {
        // testing when scope is unauthorized
        String evilZoneUserScope = SERVICEID + ".zones." + ZONE + ".evilperson";
        loadAuthentication(ZONE, evilZoneUserScope);
    }

    @Test(dataProvider = "zoneAuthRequestProvider")
    public void testDefaultAndZoneSpecificResourceAuthorization(final String zoneId, final String requestUri,
            final List<String> zoneUris, final String scope, final boolean shouldSucceed) {

        try {
            OAuth2Authentication authn = loadAuthentication(zoneId, scope, requestUri, zoneUris);
            Assert.assertNotNull(authn);
            if (!shouldSucceed) {
                Assert.fail("Authorization did not fail, as expected.");
            }
        } catch (Exception e) {
            if (shouldSucceed) {
                throw e;
            }
        }
    }

    @DataProvider
    private Object[][] zoneAuthRequestProvider() {

        return new Object[][] {
                // non zone specific request, with zone id should fail
                { ZONE, "/zone/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", false },

                // Path Traversal Tests: non zone specific request, with zone id should fail
                { ZONE, "/blah/../global/a", Arrays.asList("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { ZONE, "/blah/..\\global/a", Arrays.asList("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },

                // non zone specific request, with no zone id should pass
                { null, "/zone/a", Arrays.asList("/zone/**"), "scope.none", true },

                // zone request, with zone id should pass
                { ZONE, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },

                // zone request, with zone id , with incorrect scope , should fail
                { ZONE, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

                // zone request, with no zone id should fail
                { null, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

                // non-zone specific request with multiple uriPatterns, and pattern variations
                { ZONE, "/v1/zone/a", Arrays.asList("/v1/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { ZONE, "/admin/a", Arrays.asList("/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },

        };

    }

    private OAuth2Authentication loadAuthentication(final String zoneName, final String zoneUserScope) {
        return loadAuthentication(zoneName, zoneUserScope, "/test/resource", Arrays.asList("/zone/**"));
    }

    @SuppressWarnings("unchecked")
    private OAuth2Authentication loadAuthentication(final String zoneName, final String zoneUserScope,
            final String requestUri, final List<String> nonZoneUriPatterns) {

        ZacTokenService zacTokenServices = new ZacTokenService();
        zacTokenServices.setServiceZoneHeaders(PREDIX_ZONE_HEADER_NAME);

        Collection<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(zoneUserScope));

        OAuth2Authentication oauth2Authentication = Mockito.mock(OAuth2Authentication.class);

        Mockito.when(oauth2Authentication.isAuthenticated()).thenReturn(true);
        FastTokenServices mockFTS = Mockito.mock(FastTokenServices.class);
        Mockito.doNothing().when(mockFTS).setUseHttps(true);
        Mockito.doNothing().when(mockFTS).setStoreClaims(true);
        Mockito.doNothing().when(mockFTS).setTrustedIssuers(Matchers.anyList());
        Mockito.when(oauth2Authentication.getAuthorities()).thenReturn(authorities);
        Mockito.when(mockFTS.loadAuthentication(Matchers.anyString())).thenReturn(oauth2Authentication);

        FastTokenServicesCreator mockFTSC = Mockito.mock(FastTokenServicesCreator.class);
        when(mockFTSC.newInstance()).thenReturn(mockFTS);

        zacTokenServices.setFastRemoteTokenServicesCreator(mockFTSC);
        zacTokenServices.setServiceBaseDomain(BASE_DOMAIN);
        zacTokenServices.setServiceId(SERVICEID);

        DefaultZoneConfiguration zoneConfig = new DefaultZoneConfiguration();

        List<String> trustedIssuers;
        // Non zone specific request, using default issuer
        if (StringUtils.isEmpty(zoneName)) {
            trustedIssuers = Arrays.asList(DEFAULT_TRUSTED_ISSUER);
        // Zone specific request, using the issuers returned by mockTrustedIssuersResponseEntity
        } else {
            trustedIssuers = ZONE_TRUSTED_ISSUERS;
        }
        zoneConfig.setTrustedIssuerIds(trustedIssuers);
        zacTokenServices.setDefaultZoneConfig(zoneConfig);
        zoneConfig.setAllowedUriPatterns(nonZoneUriPatterns);

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getHeader(PREDIX_ZONE_HEADER_NAME)).thenReturn(zoneName);
        when(request.getRequestURI()).thenReturn(requestUri);
        zacTokenServices.setRequest(request);
        RestTemplate restTemplateMock = Mockito.mock(RestTemplate.class);
        zacTokenServices.setOauth2RestTemplate(restTemplateMock);
        try {
            zacTokenServices.afterPropertiesSet();
        } catch (Exception e) {
            Assert.fail("Unexpected exception after properties set on zacTokenServices " + e.getMessage());
        }

        when(restTemplateMock.getForEntity("null/v1/registration/" + SERVICEID + "/" + ZONE, TrustedIssuers.class))
                .thenReturn(mockTrustedIssuersResponseEntity());
        String accessToken = this.tokenUtil.mockAccessToken(600, zoneUserScope);
        OAuth2Authentication loadAuthentication = zacTokenServices.loadAuthentication(accessToken);

        // Making sure we are passing the right set of issuers to the FastTokenServices
        Mockito.verify(mockFTS).setTrustedIssuers(trustedIssuers);
        return loadAuthentication;
    }

    private void assertAuthentication(final OAuth2Authentication authentication, final String zoneName) {
        Assert.assertNotNull(authentication);

        if (zoneName != null) {
            // When zone is defined in request, authentication must be a ZoneOAuth2Authentication
            Assert.assertEquals(((ZoneOAuth2Authentication) authentication).getZoneId(), zoneName);
        }
    }

    public void testGetServiceHeaders() {
        ZacTokenService zts = new ZacTokenService();
        zts.setServiceZoneHeaders("a");
        Assert.assertEquals(zts.getServiceZoneHeaderList(), Arrays.asList("a"));
        zts.setServiceZoneHeaders("a,b");
        Assert.assertEquals(zts.getServiceZoneHeaderList(), Arrays.asList("a", "b"));
        zts.setServiceZoneHeaders("");
        Assert.assertEquals(zts.getServiceZoneHeaderList(), Arrays.asList(""));
    }

    private static ResponseEntity<TrustedIssuers> mockTrustedIssuersResponseEntity() {
        TrustedIssuers trustedIssuers = new TrustedIssuers(ZONE_TRUSTED_ISSUERS);
        return new ResponseEntity<TrustedIssuers>(trustedIssuers, HttpStatus.OK);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void readAccessToken() {
        ZacTokenService tokenServices = new ZacTokenService();
        String accessToken = this.tokenUtil.mockAccessToken(600);
        tokenServices.readAccessToken(accessToken);
    }
}
