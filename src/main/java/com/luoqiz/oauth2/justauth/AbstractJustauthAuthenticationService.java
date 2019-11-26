package com.luoqiz.oauth2.justauth;

import com.luoqiz.oauth2.justauth.exception.JustauthAuthenticationRedirectException;
import com.luoqiz.oauth2.justauth.provider.JustauthAuthenticationService;
import com.luoqiz.oauth2.justauth.util.ConcurrentHashMapCacheUtils;
import com.xkcoding.justauth.AuthRequestFactory;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthRequest;
import me.zhyd.oauth.utils.AuthStateUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@Slf4j
@NoArgsConstructor
@Data
public abstract class AbstractJustauthAuthenticationService<S extends AuthUser> implements JustauthAuthenticationService<S> {

    private String providerId;
    private AuthRequestFactory factory;

    public AbstractJustauthAuthenticationService(String providerId, AuthRequestFactory factory) {
        this.providerId = providerId;
        this.factory = factory;
    }

    public void afterPropertiesSet(AuthUser user) throws Exception {
    }


    @Override
    public JustauthAuthenticationToken getAuthToken(HttpServletRequest request, HttpServletResponse response) {
        //判断是否是第一次登录
        String code = request.getParameter("code");
        if (!StringUtils.hasText(code)) {
            AuthRequest authRequest = factory.get(providerId);
            String state = providerId + "::" + AuthStateUtils.createState();
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth != null) {
                log.info("auth user : {}", auth.toString());
                ConcurrentHashMapCacheUtils.setCache(state, auth, 120 * 1000);
            }

            throw new JustauthAuthenticationRedirectException(authRequest.authorize(state));
        } else if (StringUtils.hasText(code)) {
            try {
                AuthRequest authRequest = factory.get(providerId);
                AuthCallback callback = new AuthCallback();
                callback.setCode(code);
                String state = request.getParameter("state");

                callback.setState(state);
                Authentication auth = (Authentication) ConcurrentHashMapCacheUtils.getCache(state);
                if (auth != null) {
                    log.info("auth user ---- : {}", auth.toString());
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }


                AuthUser user = parseUser(authRequest.login(callback));

                afterPropertiesSet(user);

                return new JustauthAuthenticationToken(providerId, user, null, false);
            } catch (Exception e) {
                log.debug("failed to exchange for access", e);
                return null;
            }

        } else {
            return null;
        }
    }

    protected AuthUser parseUser(AuthResponse<S> response) {
        if (response.getCode() == 2000) {
            AuthUser authuser = response.getData();
            return authuser;
        }
        return null;
    }
}

