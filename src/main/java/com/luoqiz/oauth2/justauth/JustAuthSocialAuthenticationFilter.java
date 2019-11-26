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

import com.luoqiz.oauth2.justauth.connect.JustauthAuthenticationServiceRegistry;
import com.luoqiz.oauth2.justauth.handler.JustauthAuthenticationFailureHandler;
import com.luoqiz.oauth2.justauth.provider.JustauthAuthenticationService;
import com.luoqiz.oauth2.justauth.provider.JustauthUser;
import com.luoqiz.oauth2.justauth.support.ConnectionData;
import com.luoqiz.oauth2.justauth.support.UsersConnectionRepository;
import com.luoqiz.oauth2.justauth.support.jdbc.JdbcUsersConnectionRepository;
import com.xkcoding.justauth.AuthRequestFactory;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.model.AuthUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * 过滤器
 */
@Slf4j
public class JustAuthSocialAuthenticationFilter extends AbstractAuthenticationProcessingFilter {


    private final AuthRequestFactory factory;

    private UsersConnectionRepository jdbcUsersConnectionRepository;

    private SimpleUrlAuthenticationFailureHandler delegateAuthenticationFailureHandler;

    private String filterProcessesUrl = DEFAULT_FILTER_PROCESSES_URL;

    public JustAuthSocialAuthenticationFilter(AuthenticationManager authManager, AuthRequestFactory factory) {
        super(DEFAULT_FILTER_PROCESSES_URL);
//        super(new AntPathRequestMatcher(DEFAULT_FILTER_PROCESSES_URL, "GET"));
        this.factory = factory;
        this.setAuthenticationManager(authManager);
        this.delegateAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(DEFAULT_FAILURE_URL);
        super.setAuthenticationFailureHandler(new JustauthAuthenticationFailureHandler(delegateAuthenticationFailureHandler));

    }

    public JustAuthSocialAuthenticationFilter(AuthenticationManager authManager, AuthRequestFactory factory,
                                              UsersConnectionRepository usersConnectionRepository) {
        super(DEFAULT_FILTER_PROCESSES_URL);
        this.factory = factory;
        setAuthenticationManager(authManager);

        this.jdbcUsersConnectionRepository = usersConnectionRepository;

        this.delegateAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(DEFAULT_FAILURE_URL);
        super.setAuthenticationFailureHandler(new JustauthAuthenticationFailureHandler(delegateAuthenticationFailureHandler));
    }

    /**
     * 验证
     * 1：获取验证类型
     */


    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
//        if (!request.getMethod().equals("POST")) {
//            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
//        }


        Authentication auth = null;
        Set<String> authProviders = JustauthAuthenticationServiceRegistry.getInstance().getRegisteredProviderIds();
        String authProviderId = getRequestedProviderId(request);
        if (!authProviders.isEmpty() && authProviderId != null && authProviders.contains(authProviderId)) {
            JustauthAuthenticationService<?> authSerice = JustauthAuthenticationServiceRegistry.getInstance().getJustauthAuthenticationService(authProviderId);
            auth = attemptAuthService(authSerice, request, response);
            if (auth == null) {
                throw new AuthenticationServiceException("authentication failed");
            }
        }
        return auth;
    }


    /**
     * Indicates whether this filter should attempt to process a social network login request for the current invocation.
     * <p>Check if request URL matches filterProcessesUrl with valid providerId.
     * The URL must be like {filterProcessesUrl}/{providerId}.
     *
     * @return <code>true</code> if the filter should attempt authentication, <code>false</code> otherwise.
     */
    @Deprecated
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String providerId = getRequestedProviderId(request);
        if (providerId != null) {
            return true;//getAuthSource(providerId);
        }
        return false;
    }

    @SuppressWarnings("deprecation")
    @Override
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        super.setFilterProcessesUrl(filterProcessesUrl);
        this.filterProcessesUrl = filterProcessesUrl;
    }

    // private helpers
    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /*
     * Call SocialAuthenticationService.getAuthToken() to get SocialAuthenticationToken:
     *     If first phase, throw AuthenticationRedirectException to redirect to provider website.
     *     If second phase, get token/code from request parameter and call provider API to get accessToken/accessGrant.
     * Check Authentication object in spring security context, if null or not authenticated,  call doAuthentication()
     * Otherwise, it is already authenticated, add this connection.
     */
    private Authentication attemptAuthService(final JustauthAuthenticationService<?> authService, final HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        //获取登录类型
        String oauthType = getRequestedProviderId(request).toUpperCase();

        final JustauthAuthenticationToken token = authService.getAuthToken(request, response);// new JustauthAuthenticationToken(oauthType, githubUser, null, false);
        if (token == null) return null;
        Authentication auth = getAuthentication();
        //当前没有用户的情况下，执行认证操作，若是存在用户则进行绑定操作
        if (auth == null || !auth.isAuthenticated()) {
            return doAuthentication(authService, request, token);
        } else {

            //todo 绑定操作
            addConnection(authService, request, token, auth, oauthType);
            return null;
        }
    }

    protected Boolean addConnection(JustauthAuthenticationService<?> authService,
                                    HttpServletRequest request, JustauthAuthenticationToken token,
                                    Authentication auth, String oauthType) {
        List<String> user = jdbcUsersConnectionRepository.findUserIdsWithProvider(token.getProviderId(), token.getName());
        if (user.contains(token.getName())) {
            return null;
        } else {

            AuthUser authUser = (AuthUser) token.getPrincipal();

            ConnectionData connectionData = new ConnectionData(((AuthUser) token.getPrincipal()).getUsername(),
                    authUser.getSource(), authUser.getUuid(), authUser.getNickname(), authUser.getBlog(),
                    authUser.getAvatar(), authUser.getToken().getAccessToken(),
                    authUser.getToken().getOauthTokenSecret(), authUser.getToken().getRefreshToken(), new Long(authUser.getToken().getExpireIn()));
            jdbcUsersConnectionRepository.addConnection(connectionData);

        }
        return null;
    }

    private String getRequestedProviderId(HttpServletRequest request) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        // uri must start with context path
        uri = uri.substring(request.getContextPath().length());

        // remaining uri must start with filterProcessesUrl
        if (!uri.startsWith(filterProcessesUrl)) {
            return null;
        }
        uri = uri.substring(filterProcessesUrl.length());

        // expect /filterprocessesurl/provider, not /filterprocessesurlproviderr
        if (uri.startsWith("/")) {
            return uri.substring(1);
        } else {
            return null;
        }
    }

    private Authentication doAuthentication(JustauthAuthenticationService<?> authService, HttpServletRequest request, JustauthAuthenticationToken token) {
        try {
            token.setDetails(authenticationDetailsSource.buildDetails(request));
            Authentication success = getAuthenticationManager().authenticate(token);
            Assert.isInstanceOf(JustauthUser.class, success.getPrincipal(), "unexpected principle type");
            return success;
        } catch (BadCredentialsException e) {

            throw e;
        }
    }

    private static final String DEFAULT_FAILURE_URL = "/signin";
    private static final String DEFAULT_FILTER_PROCESSES_URL = "/justauth";

}
