package com.luoqiz.oauth2.justauth.service;

import com.luoqiz.oauth2.justauth.AbstractJustauthAuthenticationService;
import com.xkcoding.justauth.AuthRequestFactory;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.model.AuthUser;

@Slf4j
public class GiteeJustauthAuthenticationService<A> extends AbstractJustauthAuthenticationService<AuthUser> {

    public GiteeJustauthAuthenticationService(String providerId, AuthRequestFactory factory) {
        super(providerId, factory);
    }
}

