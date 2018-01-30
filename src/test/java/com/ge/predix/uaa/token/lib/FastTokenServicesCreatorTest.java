package com.ge.predix.uaa.token.lib;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.test.util.ReflectionTestUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.Map;

public class FastTokenServicesCreatorTest {

    FastTokenServicesCreator creator = null;

    @BeforeClass
    private void setUp() {
        creator = new FastTokenServicesCreator();
    }

    @Test
    public void testNewInstance() {
        FastTokenServices tokenServices = creator.newInstance();
        Map<String, SignatureVerifier> tokenKeys = (Map<String, SignatureVerifier>) ReflectionTestUtils.getField(tokenServices, "tokenKeys");
        Assert.assertNotNull(tokenKeys,
                "The TokenKeys Map must have been initialized");
    }
}
