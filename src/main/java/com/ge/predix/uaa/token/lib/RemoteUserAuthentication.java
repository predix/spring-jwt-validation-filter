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

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token representing a user decoded from a UAA access token.
 *
 * @author Dave Syer
 *
 */
public class RemoteUserAuthentication extends AbstractAuthenticationToken implements Authentication {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private final String id;
    private final String username;
    private final String email;

    public RemoteUserAuthentication(final String id, final String username, final String email,
            final Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.id = id;
        this.username = username;
        this.email = email;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "<N/A>";
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

    public String getId() {
        return this.id;
    }

    public String getUsername() {
        return this.username;
    }

    public String getEmail() {
        return this.email;
    }

}
