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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class DefaultZoneConfiguratorTest {

    @Test(dataProvider = "validAllowedPatterns")
    public void testValidAllowedPatterns(final List<String> allowedUriPatterns) {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(allowedUriPatterns);
        Assert.assertEquals(configurator.getAllowedUriPatterns(), allowedUriPatterns);
    }

    @Test(dataProvider = "invalidAllowedPatterns", expectedExceptions = IllegalArgumentException.class)
    public void testInvalidAllowedPatterns(final List<String> allowedUriPatterns) {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(allowedUriPatterns);
    }

    public void testSetTrustedIssuerId() {
        String expectedIssuer = "http://uaa.predix.com";
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());
        configurator.setTrustedIssuerId(expectedIssuer);

        Assert.assertEquals(configurator.getTrustedIssuerId(), expectedIssuer);
        Assert.assertEquals(configurator.getTrustedIssuerIds().size(), 1);
        Assert.assertEquals(configurator.getTrustedIssuerIds().getFirst(), expectedIssuer);
    }

    public void testSetTrustedIssuerIdNull() {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());
        configurator.setTrustedIssuerId(null);

        Assert.assertNull(configurator.getTrustedIssuerId());
        Assert.assertEquals(configurator.getTrustedIssuerIds().size(), 0);
    }

    public void testSetTrustedIssuerIdNullResetsIssuerIds() {
        List<String> expectedIssuers = Arrays.asList("http://uaa.predix.com", "http://zac-uaa.predix.com");
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());
        configurator.setTrustedIssuerIds(expectedIssuers);
        Assert.assertEquals(configurator.getTrustedIssuerIds(), expectedIssuers);
        
        //reset
        configurator.setTrustedIssuerId(null);

        Assert.assertNull(configurator.getTrustedIssuerId());
        Assert.assertEquals(configurator.getTrustedIssuerIds().size(), 0);
    }
    
    public void testMultipleTrustedIssuers() {
        List<String> expectedIssuers = Arrays.asList("http://uaa.predix.com", "http://zac-uaa.predix.com");
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());
        configurator.setTrustedIssuerIds(expectedIssuers);

        Assert.assertEquals(configurator.getTrustedIssuerIds(), expectedIssuers);
        Assert.assertEquals(configurator.getTrustedIssuerId(), expectedIssuers.getFirst());
    }

    public void testSetTrustedIssuerIdsNull() {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());
        configurator.setTrustedIssuerIds(null);

        Assert.assertEquals(configurator.getTrustedIssuerIds(), Collections.emptyList());
        Assert.assertNull(configurator.getTrustedIssuerId());
    }

    public void testSetTrustedIssuerIdsEmpty() {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());

        Assert.assertEquals(configurator.getTrustedIssuerIds(), Collections.emptyList());
        Assert.assertNull(configurator.getTrustedIssuerId());
    }

    public void testSetTrustedIssuerIdsNotInitialized() {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration(List.of());

        Assert.assertEquals(configurator.getTrustedIssuerIds(), Collections.emptyList());
        Assert.assertNull(configurator.getTrustedIssuerId());
    }

    @DataProvider
    private Object[][] validAllowedPatterns() {

        return new Object[][] { { new ArrayList<String>() }, { List.of("/zone/**") },
                                { List.of("/zone/?") }, };
    }

    @DataProvider
    private Object[][] invalidAllowedPatterns() {

        return new Object[][] { { List.of("/zone") }, { List.of("abc") }, };
    }
}