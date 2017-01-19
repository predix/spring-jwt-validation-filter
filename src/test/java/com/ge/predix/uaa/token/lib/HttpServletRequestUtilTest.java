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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class HttpServletRequestUtilTest {

    public void getSubdomain() {
        String hostname = "groot.acs.ge.com";
        String domain = "acs.ge.com";
        String actualSubdomain = HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
        String expectedSubdomain = "groot";
        Assert.assertEquals(actualSubdomain, expectedSubdomain);
    }

    public void getSubdomainForEmptyDomain() {
        String hostname = "groot.";
        String domain = "";
        String actualSubdomain = HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
        String expectedSubdomain = "groot";
        Assert.assertEquals(actualSubdomain, expectedSubdomain);
    }

    public void getSubdomainDots() {
        String hostname = "i.am.groot.acs.ge.com";
        String domain = "acs.ge.com";
        String actualSubdomain = HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
        String expectedSubdomain = "i.am.groot";
        Assert.assertEquals(actualSubdomain, expectedSubdomain);
    }

    public void getSubdomainExactMatch() {
        String hostname = "acs.ge.com";
        String domain = "acs.ge.com";
        String actualSubdomain = HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
        // If no sub-domain is provided, map to the default zone's sub-domain
        // for now. This behavior is yet to be
        // finalized. -- see US29230
        Assert.assertEquals(actualSubdomain, "");
    }

    public void getSubdomainNoMatch() {
        String hostname = "groot";
        String domain = "acs.ge.com";
        Assert.assertNull(HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain));
    }

    public void getSubdomainNoDots() {
        String hostname = "grootacs.ge.com";
        String domain = "acs.ge.com";
        Assert.assertNull(HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void getSubdomainNullDomain() {
        String hostname = "grootacs.ge.com";
        String domain = null;
        HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
    }

    public void getSubdomainEmptyDomain() {
        String hostname = "grootacs.ge.com";
        String domain = "";
        Assert.assertNull(HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void getSubdomainNullHostname() {
        String hostname = null;
        String domain = "acs.ge.com";
        HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain);
    }

    public void getSubdomainEmptyHostname() {
        String hostname = "";
        String domain = "acs.ge.com";
        Assert.assertNull(HttpServletRequestUtil.getZoneNameFromRequestHostName(hostname, domain));
    }

    @Test(dataProvider = "headersAndDomainDataProvider")
    public void testGetZoneNameWithHeaderAndBaseDomains(final String requestHostname, final String requestHeader,
            final String requestHeaderValue, final List<String> serviceBaseDomains,
            final List<String> serviceConfigHeaders, final String expectedZone) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setServerName(requestHostname);
        req.addHeader(requestHeader, requestHeaderValue);
        String actualZone = HttpServletRequestUtil.getZoneName(req, serviceBaseDomains, serviceConfigHeaders, null);
        Assert.assertEquals(actualZone, expectedZone);
    }

    @DataProvider(name = "headersAndDomainDataProvider")
    private Object[][] headersAndDomainDataProvider() {
        return new Object[][] {
                // headers only configured
                { null, "Predix-Zone-Id", "predix-test-subdomain", Collections.emptyList(),
                        Arrays.asList("Predix-Zone-Id"), "predix-test-subdomain" },
                { null, "Predix-Zone-Id", "predix-test-subdomain", Collections.emptyList(),
                        Arrays.asList("predix-zone-id"), "predix-test-subdomain" },
                { null, "predix-zone-id", "predix-test-subdomain", Collections.emptyList(),
                        Arrays.asList("Predix-Zone-Id"), "predix-test-subdomain" },
                { null, "ACS-Zone-Subdomain", "acs-test-subdomain", null,
                        Arrays.asList("Predix-Zone-Id", "ACS-Zone-Subdomain"), "acs-test-subdomain" },
                { null, "Predix-Zone-Id", "", null, Arrays.asList(""), null },
                { null, "unrecognized-headaer", "", null, Arrays.asList("Predix-Zone-Id", "ACS-Zone-Subdomain"), null },
                { null, "Predix-Zone-Id", "some-value", null, Arrays.asList("Unrecognized-Header"), null },
                // domains only configured
                { "zone1.acs.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com"), Collections.emptyList(),
                        "zone1" },
                { "zone1.acs.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com", "guardians.com"),
                        Collections.emptyList(), "zone1" },
                { "zone2.guardians.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com", "guardians.com"),
                        Collections.emptyList(), "zone2" },
                { "guardians.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com", "guardians.com"),
                        Collections.emptyList(), null },
                // headers and domains configured
                { "zone1.Guardians.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com", "Guardians.com"),
                        Arrays.asList("Predix-Zone-Id", "ACS-Zone-Subdomain"), "zone1" },
                { "zone1.Guardians.com", "Predix-Zone-Id", "DONTUSE", Arrays.asList("acs.com", "guardians.com"),
                        Arrays.asList("Predix-Zone-Id", "ACS-Zone-Subdomain"), "zone1" },
                { "zone1.Guardians.com", "Predix-Zone-Id", "DONTUSE", Collections.emptyList(), Collections.emptyList(),
                        null } };
    }

}
