package com.ge.predix.uaa.token.lib;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Test
public class DefaultZoneConfiguratorTest {

    @Test(dataProvider = "validAllowedPatters")
    public void testValidAllowedPatters(final List<String> allowedUriPatterns) {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration();
        configurator.setAllowedUriPatterns(allowedUriPatterns);

        Assert.assertEquals(configurator.getAllowedUriPatterns(), allowedUriPatterns);
    }

    @Test(dataProvider = "invalidAllowedPatters", expectedExceptions = IllegalArgumentException.class)
    public void testInvalidAllowedPatters(final List<String> allowedUriPatterns) {
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration();
        configurator.setAllowedUriPatterns(allowedUriPatterns);
    }

    public void testSingleTrustedIssuer() {
        String expectedIssuer = "http://uaa.predix.com";
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration();
        configurator.setTrustedIssuerId(expectedIssuer);

        Assert.assertEquals(configurator.getTrustedIssuerId(), expectedIssuer);
        // asserting default behavior for existing single issuer contract
        Assert.assertEquals(configurator.getTrustedIssuerIds().iterator().next(), expectedIssuer);
    }

    public void testMultipleTrustedIssuers() {
        List<String> expectedIssuers = Arrays.asList("http://uaa.predix.com", "http://zac-uaa.predix.com");
        DefaultZoneConfiguration configurator = new DefaultZoneConfiguration();
        configurator.setTrustedIssuerIds(expectedIssuers);

        Assert.assertEquals(configurator.getTrustedIssuerIds(), expectedIssuers);
        // asserting default behavior for existing single issuer contract
        Assert.assertEquals(configurator.getTrustedIssuerId(), expectedIssuers.get(0));
    }

    @DataProvider
    private Object[][] validAllowedPatters() {

        return new Object[][] { { new ArrayList<String>() }, { Arrays.asList("/zone/**") },
                { Arrays.asList("/zone/?") }, };
    }

    @DataProvider
    private Object[][] invalidAllowedPatters() {

        return new Object[][] { { Arrays.asList("/zone") }, { Arrays.asList("abc") }, };
    }
}