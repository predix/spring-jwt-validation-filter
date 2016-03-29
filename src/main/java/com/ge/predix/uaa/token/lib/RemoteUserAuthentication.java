/*******************************************************************************
 *     Cloud Foundry
 *     Copyright 2009, 2016-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
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
