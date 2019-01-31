package com.github.yantzu.springsecurity.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class JwtLogoutHandler implements LogoutHandler {

	private static final Logger LOG = LoggerFactory.getLogger(JwtLogoutHandler.class);

	private JwtTokenService jwtTokenService;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		LOG.debug("remove jwt token from cookie");
		jwtTokenService.writeTokenToResponse(response, "");
	}

	public JwtTokenService getJwtTokenService() {
		return jwtTokenService;
	}

	public void setJwtTokenService(JwtTokenService jwtTokenService) {
		this.jwtTokenService = jwtTokenService;
	}

}
