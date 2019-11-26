
package com.luoqiz.oauth2.justauth.exception;

import org.springframework.security.core.AuthenticationException;

import java.net.URL;

/**
 * 重定向到指定服务的异常。例如认证 gitee 时，会跳转到gitee服务器获取code
 */
@SuppressWarnings("serial")
public class JustauthAuthenticationRedirectException extends AuthenticationException {

    private final String redirectUrl;

    public JustauthAuthenticationRedirectException(URL redirectUrl) {
        this(redirectUrl.toString());
    }

    public JustauthAuthenticationRedirectException(String redirectUrl) {
        super("");
        this.redirectUrl = redirectUrl;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

}
