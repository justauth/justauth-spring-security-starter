package com.luoqiz.oauth2.justauth.connect;


import com.luoqiz.oauth2.justauth.provider.JustauthAuthenticationService;

import java.util.Set;

/**
 * 系统内 JustauthAuthenticationService 的标准接口
 */
public interface JustauthAuthenticationServiceFactoryLocator {

    /**
     * 获取指定 providerId 的 JustauthAuthenticationService
     * @param providerId
     * @return
     */
    JustauthAuthenticationService<?> getJustauthAuthenticationService(String providerId);

    /**
     * 获取系统内所有的 JustauthAuthenticationService 实现类的 providerId
     * @return
     */
    Set<String> getRegisteredProviderIds();

    /**
     * 注册 JustauthAuthenticationService
     * @param providerId
     * @param justauthAuthenticationService
     */
    void addJustauthAuthenticationService(String providerId, JustauthAuthenticationService<?> justauthAuthenticationService);

}
