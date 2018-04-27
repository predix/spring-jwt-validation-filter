package com.ge.predix.uaa.token.lib;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.test.util.ReflectionTestUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.benmanes.caffeine.cache.LoadingCache;

public class FastTokenServicesCreatorTest {

    FastTokenServicesCreator creator = null;

    @BeforeClass
    private void setUp() {
        creator = new FastTokenServicesCreator();
    }

    @Test
    public void testNewInstance() {
        FastTokenServices tokenServices = creator.newInstance();
        LoadingCache<String, SignatureVerifier> tokenKeys = (LoadingCache<String, SignatureVerifier>)
                ReflectionTestUtils.getField(tokenServices, "tokenKeys");
        Assert.assertNotNull(tokenKeys, "The TokenKeys Map must have been initialized");
    }
}
