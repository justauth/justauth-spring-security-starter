/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.luoqiz.oauth2.justauth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 自定义认证token
 */
public class JustauthAuthenticationToken extends AbstractAuthenticationToken {

    private final String providerId;

    private final Serializable principle;

    private final Map<String, String> providerAccountData;

    /**
     * @param providerAccountData optional extra account data
     * @param authorities
     */
    public JustauthAuthenticationToken(String providerId, Serializable principle, Map<String, String> providerAccountData,
                                       Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.providerId = providerId;

        this.principle = principle; //no principal yet
        if (providerAccountData != null) {
            this.providerAccountData = Collections.unmodifiableMap(new HashMap<String, String>(providerAccountData));
        } else {
            this.providerAccountData = Collections.emptyMap();
        }
        super.setAuthenticated(true);
    }

    /**
     * @param authorities any {@link GrantedAuthority}s for this user
     */
    public JustauthAuthenticationToken(String providerId, Serializable principle, Collection<? extends GrantedAuthority> authorities, Boolean b) {
        super(authorities);
        this.providerId = providerId;
        this.principle = principle;
        this.providerAccountData = null;
        super.setAuthenticated(b);
    }


    public String getProviderId() {
        return providerId;
    }

    /**
     * @return always null
     */
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principle;
    }

    /**
     * @return unmodifiable map, never null
     */
    public Map<String, String> getProviderAccountData() {
        return providerAccountData;
    }

    /**
     * @throws IllegalArgumentException when trying to authenticate a previously unauthenticated token
     */
    @Override
    public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
        if (!isAuthenticated) {
            super.setAuthenticated(false);
        } else if (!super.isAuthenticated()) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
    }

}
