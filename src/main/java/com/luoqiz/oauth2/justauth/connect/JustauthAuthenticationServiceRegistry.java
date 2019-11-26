package com.luoqiz.oauth2.justauth.connect;

import com.luoqiz.oauth2.justauth.provider.JustauthAuthenticationService;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 系统内所有的Justauth的认证服务
 */
public class JustauthAuthenticationServiceRegistry
        implements JustauthAuthenticationServiceFactoryLocator {

    private static ApplicationContext applicationContext = null;

    Map<String, JustauthAuthenticationService> beans = null;

    @Override
    public JustauthAuthenticationService<?> getJustauthAuthenticationService(String providerId) {
        return authenticationServices.get(providerId);
    }

    @Override
    public Set<String> getRegisteredProviderIds() {
        return authenticationServices.keySet();
    }

    @Override
    public void addJustauthAuthenticationService(String providerId, JustauthAuthenticationService<?> justauthAuthenticationService) {
        authenticationServices.put(providerId, justauthAuthenticationService);
    }

    /**
     * 单例模式
     */
    static class JustauthAuthenticationServiceRegistryInstance {
        public static final JustauthAuthenticationServiceRegistry INSTANCE = new JustauthAuthenticationServiceRegistry();
    }

    /**
     * 存放系统内所有认证服务
     */
    private static HashMap<String, JustauthAuthenticationService<?>> authenticationServices = new HashMap<>();


    public static JustauthAuthenticationServiceRegistry getInstance() {
        return JustauthAuthenticationServiceRegistryInstance.INSTANCE;
    }

}