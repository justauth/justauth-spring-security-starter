
package com.luoqiz.oauth2.justauth.handler;


import com.luoqiz.oauth2.justauth.exception.JustauthAuthenticationRedirectException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 异常处理
 */
public class JustauthAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private AuthenticationFailureHandler delegate;

	public JustauthAuthenticationFailureHandler(AuthenticationFailureHandler delegate) {
		this.delegate = delegate;
	}
	
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
		if (failed instanceof JustauthAuthenticationRedirectException) {
			response.sendRedirect(((JustauthAuthenticationRedirectException) failed).getRedirectUrl());
			return;
		}
		delegate.onAuthenticationFailure(request, response, failed);
	}

}
