/*******************************************************************************
 * Copyright 2021 General Electric Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.ge.predix.uaa.token.lib;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.collections.Lists;

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
    private static final String INVALID_ZONE = "invalidtestzone";

    public void testLoadAuthentication() {
        // testing when zone id is not null
        String zoneUserScope = SERVICEID + ".zones." + ZONE + ".user";
        assertAuthentication(loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, true,
                zoneUserScope, "/test/resource", Arrays.asList("/zone/**")), ZONE);
    }

    @SuppressWarnings("unchecked")
    @Test(expectedExceptions = IllegalStateException.class)
    public void testLoadAuthenticationNoHeaderOrBaseDomain() throws Exception {
        // testing when zone id is not null
        ZacTokenService zacTokenServices = configureZacTokenService("", null, "", true, Collections.EMPTY_LIST,
                Collections.EMPTY_LIST, null);
        zacTokenServices.afterPropertiesSet();
    }

    @Test(expectedExceptions = InvalidRequestException.class)
    public void testLoadAuthenticationNoSubdomains() throws Exception {
        // testing when zone id is not null
        String zoneUserScope = "scope.not.used";
        loadAuthenticationWithZoneAsSubdomain(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, false, zoneUserScope,
                "/test/resource", Arrays.asList("/zone/**"));
    }

    public void testLoadAuthenticationWhenZoneIdisNull() {
        // testing when zone is null, for a non-zone specific request
        assertAuthentication(loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, null, true,
                "some-other-scope", "/zone/a", Arrays.asList("/zone/**")), null);
    }

    @Test(expectedExceptions = InvalidTokenException.class)
    public void testLoadAuthenticationUnauthorizedScope() {
        // testing when scope is unauthorized
        String evilZoneUserScope = SERVICEID + ".zones." + ZONE + ".evilperson";
        loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, true, evilZoneUserScope,
                "/test/resource", Arrays.asList("/zone/**"));
    }

    @Test(
            expectedExceptions = InvalidTokenException.class,
            expectedExceptionsMessageRegExp = "Unauthorized access for zone: 'invalidtestzone'.")
    public void testLoadAuthenticationWhenZoneDoesNotExist() {
        // zone does not exist
        loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, INVALID_ZONE, true, "some-other-scope",
                "/a" + INVALID_ZONE, Arrays.asList("/zone/**"));
    }

    @Test(dataProvider = "zoneAuthRequestProvider")
    public void testDefaultAndZoneSpecificResourceAuthorization(final String zoneId, final String requestUri,
            final List<String> zoneUris, final String scope, final boolean shouldSucceed) {

        try {
            OAuth2Authentication authn = loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN,
                    zoneId, true, scope, requestUri, zoneUris);
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

    @Test
    public void testFastTokenServicesCache() throws Exception {
        ZacTokenService zacTokenService = Mockito.spy(new ZacTokenService());
        zacTokenService.setIssuersTtlSeconds(10);
        zacTokenService.setOauth2RestTemplate(configureMockRestTemplate());
        zacTokenService.setServiceId(SERVICEID);
        zacTokenService.afterPropertiesSet();

        // Verify that FastTokenServices is created and put in the cache
        FastTokenServices fts = zacTokenService.getOrCreateZoneTokenService(ZONE);
        Assert.assertNotNull(fts);
        Mockito.verify(zacTokenService, times(1)).createFastTokenService(ZONE);

        // Verify that FastTokenServices is obtained from the cache
        fts = zacTokenService.getOrCreateZoneTokenService(ZONE);
        Assert.assertNotNull(fts);
        Mockito.verify(zacTokenService, times(1)).createFastTokenService(ZONE);
    }

    @Test(expectedExceptions = HttpClientErrorException.class)
    public void testFastTokenServicesCacheException() throws Exception {
        ZacTokenService zacTokenService = new ZacTokenService();
        zacTokenService.setIssuersTtlSeconds(10);
        zacTokenService.setOauth2RestTemplate(configureMockRestTemplate());
        zacTokenService.setServiceId(SERVICEID);
        zacTokenService.afterPropertiesSet();

        zacTokenService.getOrCreateZoneTokenService(INVALID_ZONE);
    }

    @DataProvider
    private Object[][] zoneAuthRequestProvider() {

        return new Object[][] {
                // non zone specific request, with a token from zone trusted issuer should fail
                { ZONE, "/zone/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", false },

                // Path Traversal Tests: non zone specific request with a token from zone trusted issuer should fail
                { ZONE, "/blah/../global/a", Arrays.asList("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { ZONE, "/blah\\/../global/a", Arrays.asList("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { ZONE, "/blah/%2e%2e/global/a", Arrays.asList("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },

                // non zone specific request with a token from default trusted issuer should pass
                { null, "/zone/a", Arrays.asList("/zone/**"), "scope.none", true },
                { null, "/blah/../zone/a", Arrays.asList("/zone/**"), "scope.none", true },
                { null, "/blah/%2e%2e/zone/a", Arrays.asList("/zone/**"), "scope.none", true },

                // zone request with a token from zone trusted issuer should pass
                { ZONE, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },

                // zone request with a token from zone trusted issuer but incorrect scope should fail
                { ZONE, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

                // zone request without token from zone trusted issuer should fail
                { null, "/a", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

                // non-zone specific request with multiple uriPatterns, and pattern variations
                { ZONE, "/v1/zone/a", Arrays.asList("/v1/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { ZONE, "/admin/a", Arrays.asList("/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                        false },
                { null, "/blah/../zone/a", Arrays.asList("/zone/**", "/admin/**"), "scope.none", true },
                { null, "/blah/%2e%2e/admin/a", Arrays.asList("/zone/**", "/admin/**"), "scope.none", true },

                // request with relative path that could not be normalized because of a special character;
                // as a result, such requests are considered as a zone-specific requests
                { ZONE, "/a/..\\zone/", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },
                { ZONE, "/a/..?zone/", Arrays.asList("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },
                { null, "/a/..\\zone/", Arrays.asList("/zone/**"), SERVICEID + "scope.none", false },
        };
    }

    private OAuth2Authentication loadAuthenticationWithZoneAsHeader(final String configuredHeaderNames,
            final String configuredBaseDomains, final String requestZoneName, final Boolean useSubdomainsForZones,
            final String userScopes, final String requestUri, final List<String> nonZoneUriPatterns) {

        FastTokenServices mockFTS = mockFastTokenService(userScopes);
        FastTokenServicesCreator mockFTSC = Mockito.mock(FastTokenServicesCreator.class);
        when(mockFTSC.newInstance()).thenReturn(mockFTS);

        HttpServletRequest request = mockHttpRequestWithZoneAsHeader(requestZoneName, requestUri);

        List<String> trustedIssuers = configureTrustedIssuers(requestZoneName);
        ZacTokenService zacTokenServices = configureZacTokenService(configuredHeaderNames, mockFTSC,
                configuredBaseDomains, useSubdomainsForZones, trustedIssuers, nonZoneUriPatterns, request);

        return executeZacTokenServices(zacTokenServices, mockFTS, trustedIssuers, userScopes);
    }

    private OAuth2Authentication loadAuthenticationWithZoneAsSubdomain(final String configuredHeaderNames,
            final String configuredBaseDomains, final String requestZoneName, final Boolean useSubdomainsForZones,
            final String userScopes, final String requestUri, final List<String> nonZoneUriPatterns) {

        FastTokenServices mockFTS = mockFastTokenService(userScopes);
        FastTokenServicesCreator mockFTSC = Mockito.mock(FastTokenServicesCreator.class);
        when(mockFTSC.newInstance()).thenReturn(mockFTS);

        HttpServletRequest request = mockHttpRequestWithZoneAsSubdomain(requestZoneName, requestUri);

        List<String> trustedIssuers = configureTrustedIssuers(requestZoneName);
        ZacTokenService zacTokenServices = configureZacTokenService(configuredHeaderNames, mockFTSC,
                configuredBaseDomains, useSubdomainsForZones, trustedIssuers, nonZoneUriPatterns, request);

        return executeZacTokenServices(zacTokenServices, mockFTS, trustedIssuers, userScopes);
    }

    private OAuth2Authentication executeZacTokenServices(final ZacTokenService zacTokenServices, final FastTokenServices mockFTS,
            final List<String> trustedIssuers, final String userScopes) {
        try {
            zacTokenServices.afterPropertiesSet();
        } catch (Exception e) {
            Assert.fail("Unexpected exception after properties set on zacTokenServices " + e.getMessage());
        }
        String accessToken = this.tokenUtil.mockAccessToken(600, userScopes);
        OAuth2Authentication loadAuthentication = zacTokenServices.loadAuthentication(accessToken);

        // Making sure we are passing the right set of issuers to the FastTokenServices
        Mockito.verify(mockFTS).setTrustedIssuers(trustedIssuers);
        return loadAuthentication;
    }

    private HttpServletRequest mockHttpRequestWithZoneAsHeader(final String requestZoneName, final String requestUri) {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getHeader(PREDIX_ZONE_HEADER_NAME)).thenReturn(requestZoneName);
        when(request.getRequestURI()).thenReturn(requestUri);
        return request;

    }

    private HttpServletRequest mockHttpRequestWithZoneAsSubdomain(final String requestZoneName, final String requestUri) {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn(requestZoneName + ".localhost");
        when(request.getRequestURI()).thenReturn(requestUri);
        return request;

    }

    private List<String> configureTrustedIssuers(final String requestZoneName) {
        List<String> trustedIssuers;
        // Non zone specific request, using default issuer
        if (StringUtils.isEmpty(requestZoneName)) {
            trustedIssuers = Arrays.asList(DEFAULT_TRUSTED_ISSUER);
            // Zone specific request, using the issuers returned by mockTrustedIssuersResponseEntity
        } else {
            trustedIssuers = ZONE_TRUSTED_ISSUERS;
        }
        return trustedIssuers;
    }

    private ZacTokenService configureZacTokenService(final String configuredHeaderNames, final FastTokenServicesCreator mockFTSC,
            final String configuredBaseDomains, final Boolean useSubdomainsForZones, final List<String> trustedIssuers,
            final List<String> nonZoneUriPatterns, final HttpServletRequest request) {

        ZacTokenService zacTokenServices = new ZacTokenService();
        RestTemplate mockRestTemplate = configureMockRestTemplate();
        DefaultZoneConfiguration zoneConfig = new DefaultZoneConfiguration();

        zoneConfig.setTrustedIssuerIds(trustedIssuers);
        zoneConfig.setAllowedUriPatterns(nonZoneUriPatterns);

        zacTokenServices.setDefaultZoneConfig(zoneConfig);
        zacTokenServices.setServiceZoneHeaders(configuredHeaderNames);
        zacTokenServices.setFastRemoteTokenServicesCreator(mockFTSC);
        zacTokenServices.setServiceBaseDomain(configuredBaseDomains);
        zacTokenServices.setServiceId(SERVICEID);
        zacTokenServices.setUseSubdomainsForZones(useSubdomainsForZones);
        zacTokenServices.setOauth2RestTemplate(mockRestTemplate);
        zacTokenServices.setRequest(request);

        return zacTokenServices;
    }

    private RestTemplate configureMockRestTemplate() {
        RestTemplate restTemplateMock = Mockito.mock(RestTemplate.class);

        when(restTemplateMock.getForEntity("null/v1/registration/" + SERVICEID + "/" + ZONE, TrustedIssuers.class))
                .thenReturn(mockTrustedIssuersResponseEntity());

        when(restTemplateMock.getForEntity("null/v1/registration/" + SERVICEID + "/" + INVALID_ZONE,
                TrustedIssuers.class)).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND));

        return restTemplateMock;
    }

    @SuppressWarnings("unchecked")
    private FastTokenServices mockFastTokenService(final String userScopes) {

        Collection<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(userScopes));

        OAuth2Authentication oauth2Authentication = Mockito.mock(OAuth2Authentication.class);

        Mockito.when(oauth2Authentication.isAuthenticated()).thenReturn(true);
        FastTokenServices mockFTS = Mockito.mock(FastTokenServices.class);
        Mockito.doNothing().when(mockFTS).setUseHttps(true);
        Mockito.doNothing().when(mockFTS).setStoreClaims(true);
        Mockito.doNothing().when(mockFTS).setTrustedIssuers(Matchers.anyList());
        Mockito.when(oauth2Authentication.getAuthorities()).thenReturn(authorities);
        Mockito.when(mockFTS.loadAuthentication(Matchers.anyString())).thenReturn(oauth2Authentication);
        return mockFTS;

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
        Assert.assertEquals(zts.getServiceZoneHeadersList(), Arrays.asList("a"));
        zts.setServiceZoneHeaders("a,b");
        Assert.assertEquals(zts.getServiceZoneHeadersList(), Arrays.asList("a", "b"));
        zts.setServiceZoneHeaders("");
        Assert.assertEquals(zts.getServiceZoneHeadersList(), Collections.emptyList());
    }

    private static ResponseEntity<TrustedIssuers> mockTrustedIssuersResponseEntity() {
        TrustedIssuers trustedIssuers = new TrustedIssuers(ZONE_TRUSTED_ISSUERS);
        return new ResponseEntity<>(trustedIssuers, HttpStatus.OK);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void readAccessToken() {
        ZacTokenService tokenServices = new ZacTokenService();
        String accessToken = this.tokenUtil.mockAccessToken(600);
        tokenServices.readAccessToken(accessToken);
    }

    @Test(dataProvider = "requestUriProvider")
    public void testNormalizeUri(final String requestUri, final String expectedUri) {
        ZoneAwareFastTokenService tokenService = new ZoneAwareFastTokenService();
        Assert.assertEquals(tokenService.normalizeUri(requestUri), expectedUri);
    }

    @DataProvider
    private Object[][] requestUriProvider() {
        return combine(path(), pathWithSpecialCharacters(), relativePath(), relativePathWithSpecialCharacters());
    }

    private Object[][] path() {
        return new Object[][] { { "/v1/admin", "/v1/admin" } };
    }

    private Object[][] pathWithSpecialCharacters() {
        return new Object[][] { { "/v1/subject/joe%40gmail.com", "/v1/subject/joe@gmail.com" },
                { "/v1/subject/Jane%20Doe", "/v1/subject/Jane%20Doe" },
                { "/v1/subject/Jane Doe", "/v1/subject/Jane%20Doe" } };
    }

    private Object[][] relativePath() {
        return new Object[][] { { "/v1/hello/../admin", "/v1/admin" }, { "/v1/hello/%2e%2e/admin", "/v1/admin" } };
    }

    private Object[][] relativePathWithSpecialCharacters() {
        return new Object[][] { { "/v1/hello/%2e%2e/policy-set/my%20policy%20set", "/v1/policy-set/my%20policy%20set" },
                { "/v1/hello/%2e%2e/resource/%2Falarms%2Fsites%2Fsanramon", "/v1/resource/alarms/sites/sanramon" },
                { "/blah/..\\global/a", "/blah/..%5Cglobal/a" }, { "/blah\\../global/a", "/blah%5C../global/a" },
                { "/blah\\/../global/a", "/global/a" }, { "/blah/../\\global/a", "/%5Cglobal/a" },
                { "/blah/..?global/a", "/blah/..%3Fglobal/a" } };
    }

    private static Object[][] combine(final Object[][]... testData) {
        List<Object[]> result = Lists.newArrayList();
        for (Object[][] t : testData) {
            result.addAll(Arrays.asList(t));
        }
        return result.toArray(new Object[result.size()][]);
    }
}
