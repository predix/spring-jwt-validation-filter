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

import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_ISSUER_ID;
import static com.ge.predix.uaa.token.lib.TestTokenUtil.TOKEN_KEY_RESPONSE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
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
    private static final List<String> ZONE_TRUSTED_ISSUERS = Arrays.asList("http://myuaa.com",
            "http://localhost:8080/uaa/oauth/token");
    private static final String INVALID_ZONE = "invalidtestzone";

    public void testLoadAuthentication() {
        // testing when zone id is not null
        String zoneUserScope = SERVICEID + ".zones." + ZONE + ".user";
        assertAuthentication(loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, true,
                                                                zoneUserScope, "/test/resource", List.of("/zone/**")), ZONE);
    }

    @SuppressWarnings("unchecked")
    @Test(expectedExceptions = IllegalStateException.class)
    public void testLoadAuthenticationNoHeaderOrBaseDomain() throws Exception {
        // testing when zone id is not null
        ZacTokenService zacTokenServices = configureZacTokenService("", null, "", true, Collections.EMPTY_LIST,
                Collections.EMPTY_LIST, null);
        zacTokenServices.afterPropertiesSet();
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testLoadAuthenticationNoSubdomains() throws Exception {
        // testing when zone id is not null
        String zoneUserScope = "scope.not.used";
        loadAuthenticationWithZoneAsSubdomain(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, false, zoneUserScope,
                                              "/test/resource", List.of("/zone/**"));
    }

    public void testLoadAuthenticationWhenZoneIdisNull() {
        // testing when zone is null, for a non-zone specific request
        assertAuthentication(loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, null, true,
                                                                "some-other-scope", "/zone/a", List.of("/zone/**")), null);
    }

    @Test(expectedExceptions = InvalidBearerTokenException.class)
    public void testLoadAuthenticationUnauthorizedScope() {
        // testing when scope is unauthorized
        String evilZoneUserScope = SERVICEID + ".zones." + ZONE + ".evilperson";
        loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, ZONE, true, evilZoneUserScope,
                                           "/test/resource", List.of("/zone/**"));
    }

    @Test(
            expectedExceptions = InvalidBearerTokenException.class,
            expectedExceptionsMessageRegExp = "Unauthorized access for zone: 'invalidtestzone'.")
    public void testLoadAuthenticationWhenZoneDoesNotExist() {
        // zone does not exist
        loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN, INVALID_ZONE, true, "some-other-scope",
                "/a" + INVALID_ZONE, List.of("/zone/**"));
    }

    @Test(dataProvider = "zoneAuthRequestProvider")
    public void testDefaultAndZoneSpecificResourceAuthorization(final String zoneId, final String requestUri,
            final List<String> zoneUris, final String scope, final boolean shouldSucceed) {

        try {
            Authentication authn = loadAuthenticationWithZoneAsHeader(PREDIX_ZONE_HEADER_NAME, BASE_DOMAIN,
                    zoneId, true, scope, requestUri, zoneUris);
            assertNotNull(authn);
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
    public void testFastTokenServicesCache() {
        ZacTokenService zacTokenService = getZacTokenService(ZONE);
        FastTokenServices fastTokenServices = mockFastTokenService();
        when(zacTokenService.createFastTokenService(ZONE)).thenReturn(fastTokenServices);
        // Verify that FastTokenServices is created and put in the cache
        FastTokenServices fts = zacTokenService.getOrCreateZoneTokenService(ZONE);
        assertNotNull(fts);
        Mockito.verify(zacTokenService, times(1)).createFastTokenService(ZONE);
        Mockito.clearInvocations(zacTokenService);
        // Verify that FastTokenServices is obtained from the cache
        fts = zacTokenService.getOrCreateZoneTokenService(ZONE);
        assertNotNull(fts);
        Mockito.verify(zacTokenService, times(1)).createFastTokenService(ZONE);
    }

    private ZacTokenService getZacTokenService(String zoneId) {
        ZacTokenService zacTokenService = mock(ZacTokenService.class);
        when(zacTokenService.getOrCreateZoneTokenService(zoneId)).thenCallRealMethod();
        when(zacTokenService.getServiceBaseDomainList()).thenReturn(List.of(BASE_DOMAIN));
        when(zacTokenService.getServiceZoneHeadersList()).thenReturn(List.of(PREDIX_ZONE_HEADER_NAME));
        Mockito.doCallRealMethod().when(zacTokenService).afterPropertiesSet();
        zacTokenService.setIssuersTtlSeconds(10);
        zacTokenService.afterPropertiesSet();
        return zacTokenService;
    }

    @Test(expectedExceptions = HttpClientErrorException.class)
    public void testFastTokenServicesCacheException() {
        ZacTokenService zacTokenService = getZacTokenService(INVALID_ZONE);
        when(zacTokenService.createFastTokenService(INVALID_ZONE)).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND));
        zacTokenService.getOrCreateZoneTokenService(INVALID_ZONE);
    }

    @DataProvider
    private Object[][] zoneAuthRequestProvider() {

        return new Object[][] {
            // non zone specific request, with a token from zone trusted issuer should fail
            { ZONE, "/zone/a", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", false },

            // Path Traversal Tests: non zone specific request with a token from zone trusted issuer should fail
            {
                ZONE, "/blah/../global/a", List.of("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                false
            },
            {
                ZONE, "/blah\\/../global/a", List.of("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                false
            },
            {
                ZONE, "/blah/%2e%2e/global/a", List.of("/global/**"), SERVICEID + ".zones." + ZONE + ".user",
                false
            },

            // non zone specific request with a token from default trusted issuer should pass
            { null, "/zone/a", List.of("/zone/**"), "scope.none", true },
            { null, "/blah/../zone/a", List.of("/zone/**"), "scope.none", true },
            { null, "/blah/%2e%2e/zone/a", List.of("/zone/**"), "scope.none", true },

            // zone request with a token from zone trusted issuer should pass
            { ZONE, "/a", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },

            // zone request with a token from zone trusted issuer but incorrect scope should fail
            { ZONE, "/a", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

            // zone request without token from zone trusted issuer should fail
            { null, "/a", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".blah", false },

            // non-zone specific request with multiple uriPatterns, and pattern variations
            {
                ZONE, "/v1/zone/a", List.of("/v1/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                false
            },
            {
                ZONE, "/admin/a", List.of("/zone/**", "/admin/**"), SERVICEID + ".zones." + ZONE + ".user",
                false
            },
            { null, "/blah/../zone/a", List.of("/zone/**", "/admin/**"), "scope.none", true },
            { null, "/blah/%2e%2e/admin/a", List.of("/zone/**", "/admin/**"), "scope.none", true },

            // request with relative path that could not be normalized because of a special character;
            // as a result, such requests are considered as a zone-specific requests
            { ZONE, "/a/..\\zone/", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },
            { ZONE, "/a/..?zone/", List.of("/zone/**"), SERVICEID + ".zones." + ZONE + ".user", true },
            { null, "/a/..\\zone/", List.of("/zone/**"), SERVICEID + "scope.none", false },
            };
    }

    private Authentication loadAuthenticationWithZoneAsHeader(final String configuredHeaderNames,
            final String configuredBaseDomains, final String requestZoneName, final Boolean useSubdomainsForZones,
            final String userScopes, final String requestUri, final List<String> nonZoneUriPatterns) {

        FastTokenServices mockFTS = mockFastTokenService();
        FastTokenServicesCreator mockFTSC = mock(FastTokenServicesCreator.class);
        when(mockFTSC.newInstance()).thenReturn(mockFTS);

        HttpServletRequest request = mockHttpRequestWithZoneAsHeader(requestZoneName, requestUri);

        List<String> trustedIssuers = configureTrustedIssuers(requestZoneName);
        ZacTokenService zacTokenServices = configureZacTokenService(configuredHeaderNames, mockFTSC,
                configuredBaseDomains, useSubdomainsForZones, trustedIssuers, nonZoneUriPatterns, request);
        return executeZacTokenServices(zacTokenServices, mockFTS, userScopes);
    }

    private Authentication loadAuthenticationWithZoneAsSubdomain(final String configuredHeaderNames,
            final String configuredBaseDomains, final String requestZoneName, final Boolean useSubdomainsForZones,
            final String userScopes, final String requestUri, final List<String> nonZoneUriPatterns) {

        FastTokenServices mockFTS = mockFastTokenService();
        FastTokenServicesCreator mockFTSC = mock(FastTokenServicesCreator.class);
        when(mockFTSC.newInstance()).thenReturn(mockFTS);

        HttpServletRequest request = mockHttpRequestWithZoneAsSubdomain(requestZoneName, requestUri);

        List<String> trustedIssuers = configureTrustedIssuers(requestZoneName);
        ZacTokenService zacTokenServices = configureZacTokenService(configuredHeaderNames, mockFTSC,
                configuredBaseDomains, useSubdomainsForZones, trustedIssuers, nonZoneUriPatterns, request);
        return executeZacTokenServices(zacTokenServices, mockFTS, userScopes);
    }

    private Authentication executeZacTokenServices(final ZacTokenService zacTokenServices, FastTokenServices mockFTS,
                                                   String userScopes) {
        try {
            zacTokenServices.afterPropertiesSet();
            LoadingCache<Object, Object>
                tokenServicesCache = Caffeine.newBuilder().expireAfterWrite(86400, TimeUnit.SECONDS).build(o-> mockFTS);
            tokenServicesCache.put("testzone1", mockFTS);
            ReflectionTestUtils.setField(zacTokenServices, "tokenServicesCache", tokenServicesCache);
        } catch (Exception e) {
            Assert.fail("Unexpected exception after properties set on zacTokenServices " + e.getMessage());
        }
        String token =
            this.tokenUtil.mockAccessToken(TOKEN_ISSUER_ID,60, userScopes);
        return zacTokenServices.authenticate(new BearerTokenAuthenticationToken(token));
    }

    private HttpServletRequest mockHttpRequestWithZoneAsHeader(final String requestZoneName, final String requestUri) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn("localhost");
        when(request.getHeader(PREDIX_ZONE_HEADER_NAME)).thenReturn(requestZoneName);
        when(request.getRequestURI()).thenReturn(requestUri);
        return request;

    }

    private HttpServletRequest mockHttpRequestWithZoneAsSubdomain(final String requestZoneName, final String requestUri) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServerName()).thenReturn(requestZoneName + ".localhost");
        when(request.getRequestURI()).thenReturn(requestUri);
        return request;

    }

    private List<String> configureTrustedIssuers(final String requestZoneName) {
        List<String> trustedIssuers;
        // Non zone specific request, using default issuer
        if (StringUtils.isEmpty(requestZoneName)) {
            trustedIssuers = List.of(TOKEN_ISSUER_ID);
            // Zone specific request, using the issuers returned by mockTrustedIssuersResponseEntity
        } else {
            trustedIssuers = ZONE_TRUSTED_ISSUERS;
        }
        return trustedIssuers;
    }

    private ZacTokenService configureZacTokenService(final String configuredHeaderNames, final FastTokenServicesCreator mockFTSC,
            final String configuredBaseDomains, final Boolean useSubdomainsForZones, final List<String> trustedIssuers,
            final List<String> nonZoneUriPatterns, final HttpServletRequest request) {

        DefaultZoneConfiguration zoneConfig = new DefaultZoneConfiguration(nonZoneUriPatterns);
        zoneConfig.setTrustedIssuerIds(trustedIssuers);

        ClientRegistration mockRegistration = mock(ClientRegistration.class);
        when(mockRegistration.getRegistrationId()).thenReturn("testClientRegistrationId");
        ZacTokenService zacTokenServices = new ZacTokenService(SERVICEID, zoneConfig, "", request, mockRegistration);
        zacTokenServices.setServiceZoneHeaders(configuredHeaderNames);
        zacTokenServices.setFastRemoteTokenServicesCreator(mockFTSC);
        zacTokenServices.setServiceBaseDomain(configuredBaseDomains);
        zacTokenServices.setUseSubdomainsForZones(useSubdomainsForZones);
        return zacTokenServices;
    }

    private RestTemplate configureMockRestTemplate() {
        RestTemplate restTemplateMock = mock(RestTemplate.class);

        when(restTemplateMock.getForEntity("null/v1/registration/" + SERVICEID + "/" + ZONE, TrustedIssuers.class))
                .thenReturn(mockTrustedIssuersResponseEntity());

        when(restTemplateMock.getForEntity("null/v1/registration/" + SERVICEID + "/" + INVALID_ZONE,
                TrustedIssuers.class)).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND));

        return restTemplateMock;
    }

    private FastTokenServices mockFastTokenService() {
        BearerTokenAuthenticationToken jwtAuthenticationToken = mock(BearerTokenAuthenticationToken.class);
        Mockito.when(jwtAuthenticationToken.isAuthenticated()).thenReturn(true);
        FastTokenServices fastTokenServices = new FastTokenServices();
        RestTemplate mockRestTemplate = mock(RestTemplate.class);
        fastTokenServices.setRestTemplate(mockRestTemplate);
        fastTokenServices.setTrustedIssuers(List.of(TOKEN_ISSUER_ID));
        when(mockRestTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
            .thenReturn(new ResponseEntity<>(TOKEN_KEY_RESPONSE, HttpStatus.OK));
        return fastTokenServices;
    }

    private void assertAuthentication(final Authentication authentication, final String zoneName) {
        assertNotNull(authentication);

        if (zoneName != null) {
            // When zone is defined in request, authentication must be a ZoneOAuth2Authentication
            Assert.assertEquals(((ZoneOAuth2Authentication) authentication).getZoneId(), zoneName);
        }
    }

    public void testGetServiceHeaders() {
        ZacTokenService zts = configureZacTokenService("", null, "", true, Collections.EMPTY_LIST,
                                                       Collections.EMPTY_LIST, null);
        zts.setServiceZoneHeaders("a");
        Assert.assertEquals(zts.getServiceZoneHeadersList(), List.of("a"));
        zts.setServiceZoneHeaders("a,b");
        Assert.assertEquals(zts.getServiceZoneHeadersList(), List.of("a", "b"));
        zts.setServiceZoneHeaders("");
        Assert.assertEquals(zts.getServiceZoneHeadersList(), Collections.emptyList());
    }

    private static ResponseEntity<TrustedIssuers> mockTrustedIssuersResponseEntity() {
        TrustedIssuers trustedIssuers = new TrustedIssuers(ZONE_TRUSTED_ISSUERS);
        return new ResponseEntity<>(trustedIssuers, HttpStatus.OK);
    }

    @Test(dataProvider = "requestUriProvider")
    public void testNormalizeUri(final String requestUri, final String expectedUri) {
        ZoneAwareFastTokenService tokenService = new ZoneAwareFastTokenService("", null, null);
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
