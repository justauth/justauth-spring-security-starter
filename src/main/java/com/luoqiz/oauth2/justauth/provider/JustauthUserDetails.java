package com.luoqiz.oauth2.justauth.provider;

import org.springframework.security.core.userdetails.UserDetails;

public interface JustauthUserDetails extends UserDetails {

	String getUserId();
	
}
