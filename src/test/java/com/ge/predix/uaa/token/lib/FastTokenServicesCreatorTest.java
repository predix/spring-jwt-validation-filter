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

import com.nimbusds.jose.crypto.RSASSAVerifier;
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
        LoadingCache<String, RSASSAVerifier> tokenKeys = (LoadingCache<String, RSASSAVerifier>)
                ReflectionTestUtils.getField(tokenServices, "tokenKeys");
        Assert.assertNotNull(tokenKeys, "The TokenKeys Map must have been initialized");
    }
}
