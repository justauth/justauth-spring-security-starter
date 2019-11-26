package com.luoqiz.oauth2.justauth;

import com.luoqiz.oauth2.justauth.provider.JustauthUserDetailsService;
import com.luoqiz.oauth2.justauth.support.UsersConnectionRepository;
import com.luoqiz.oauth2.justauth.support.jdbc.JdbcUsersConnectionRepository;
import me.zhyd.oauth.model.AuthUser;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * 从第三方正确获取用户信息后，自系统用户处理
 */
public class JustauthAuthenticationProvider implements AuthenticationProvider {

    private UsersConnectionRepository usersConnectionRepository;

    private JustauthUserDetailsService userDetailsService;

    public JustauthAuthenticationProvider(UsersConnectionRepository usersConnectionRepository, JustauthUserDetailsService userDetailsService) {
        this.usersConnectionRepository = usersConnectionRepository;
        this.userDetailsService = userDetailsService;
    }

    public boolean supports(Class<? extends Object> authentication) {
        return JustauthAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Authenticate user based on {@link JustauthAuthenticationToken}
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(JustauthAuthenticationToken.class, authentication, "unsupported justAuth authentication type");
        Assert.isTrue(!authentication.isAuthenticated(), "already authenticated");
        JustauthAuthenticationToken authToken = (JustauthAuthenticationToken) authentication;
        String providerId = authToken.getProviderId();
        AuthUser authUser = (AuthUser) authToken.getPrincipal();
        String userId = toUserId(authUser);
        if (userId == null) {
            throw new BadCredentialsException("Unknown access token");
        }

        UserDetails userDetails = userDetailsService.loadUserByUserId(userId);
        if (userDetails == null) {
            throw new UsernameNotFoundException("Unknown connected account id");
        }

        return new JustauthAuthenticationToken(providerId, userDetails, getAuthorities(providerId, userDetails), true);
    }

    protected String toUserId(AuthUser authUser) {
        Set<String> providerUserIds = new HashSet<>(1);
        providerUserIds.add(authUser.getUuid());
        Set<String> userIds = usersConnectionRepository.findUserIdsConnectedTo(authUser.getSource(), providerUserIds);
        // only if a single userId is connected to this providerUserId
        return (userIds.size() == 1) ? userIds.iterator().next() : null;
    }


    protected Collection<? extends GrantedAuthority> getAuthorities(String providerId, UserDetails userDetails) {
        return userDetails.getAuthorities();
    }

}
