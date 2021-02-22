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

/**
 * <code>FastTokenServicesCreator</code> not meant for public use: use <code>ZacTokenServices</code> instead.
 */
public class FastTokenServicesCreator {

    /**
     * @return an instance of {@link FastTokenServices} with indefinite caching of issuer public keys.
     */
    public FastTokenServices newInstance() {
        return new FastTokenServices();
    }
}
