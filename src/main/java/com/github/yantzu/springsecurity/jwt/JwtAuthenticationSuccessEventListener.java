package com.github.yantzu.springsecurity.jwt;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class JwtAuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

	private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationSuccessEventListener.class);

	private JwtTokenService jwtTokenService;

	@Override
	public void onApplicationEvent(AuthenticationSuccessEvent authorizedEvent) {
		LOG.debug("add jwt token to cookie");
		HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
				.getResponse();
		
		jwtTokenService.writeTokenToResponse(response, authorizedEvent.getAuthentication());
	}

	public JwtTokenService getJwtTokenService() {
		return jwtTokenService;
	}

	public void setJwtTokenService(JwtTokenService jwtTokenService) {
		this.jwtTokenService = jwtTokenService;
	}
}
