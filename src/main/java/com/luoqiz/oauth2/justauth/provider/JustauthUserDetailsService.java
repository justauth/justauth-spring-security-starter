package com.luoqiz.oauth2.justauth.provider;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 获取用户信息
 */
public interface JustauthUserDetailsService {

    /**
     * @param userId the user ID used to lookup the user details
     * @return the JustauthUserDetails requested
     * @see UserDetailsService#loadUserByUsername(String)
     */
    JustauthUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException;
}
