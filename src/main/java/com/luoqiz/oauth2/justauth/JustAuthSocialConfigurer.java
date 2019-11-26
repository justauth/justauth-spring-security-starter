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
import com.luoqiz.oauth2.justauth.provider.JustauthUserDetailsService;
import com.luoqiz.oauth2.justauth.service.GiteeJustauthAuthenticationService;
import com.luoqiz.oauth2.justauth.service.GithubJustauthAuthenticationService;
import com.luoqiz.oauth2.justauth.service.GoogleJustauthAuthenticationService;
import com.luoqiz.oauth2.justauth.support.UsersConnectionRepository;
import com.luoqiz.oauth2.justauth.support.jdbc.JdbcUsersConnectionRepository;
import com.xkcoding.justauth.AuthRequestFactory;
import lombok.Data;
import me.zhyd.oauth.model.AuthUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 系统配置过滤器
 */
@Data
public class JustAuthSocialConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private AuthRequestFactory factory;
    private UsersConnectionRepository jdbcUsersConnectionRepository;
    private JustauthUserDetailsService userDetailsService;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;

    public JustAuthSocialConfigurer(AuthRequestFactory factory, UsersConnectionRepository jdbcUsersConnectionRepository) {
        this.factory = factory;
        this.jdbcUsersConnectionRepository = jdbcUsersConnectionRepository;
    }

    /**
     * 此组件已经实现的服务
     */
    private void justauthAuthenticationServiceRegistry() {
        JustauthAuthenticationServiceRegistry.getInstance().addJustauthAuthenticationService("github", new GithubJustauthAuthenticationService<>("github", factory));
        JustauthAuthenticationServiceRegistry.getInstance().addJustauthAuthenticationService("google", new GoogleJustauthAuthenticationService<>("google", factory));
        JustauthAuthenticationServiceRegistry.getInstance().addJustauthAuthenticationService("gitee", new GiteeJustauthAuthenticationService<>("gitee", factory));
    }

    /**
     * 添加自定义  JustauthAuthenticationService 服务
     *
     * @param key
     * @param service
     */
    public void addJustauthAuthenticationService(String key, AbstractJustauthAuthenticationService<AuthUser> service) {
        service.setFactory(factory);
        JustauthAuthenticationServiceRegistry.getInstance().addJustauthAuthenticationService(key, service);
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        justauthAuthenticationServiceRegistry();
        JustAuthSocialAuthenticationFilter filter = new JustAuthSocialAuthenticationFilter(
                http.getSharedObject(AuthenticationManager.class), factory, jdbcUsersConnectionRepository);
        filter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(authenticationFailureHandler);
        http.authenticationProvider(
                new JustauthAuthenticationProvider(jdbcUsersConnectionRepository, userDetailsService))
//                .addFilterBefore(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
                .addFilterBefore(postProcess(filter), AnonymousAuthenticationFilter.class);
    }

}
