package com.github.yantzu.springsecurity.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

	private JwtTokenService jwtTokenService;
	private UserDetailsService userDetailsService;
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	protected boolean isLoggedIn() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof AnonymousAuthenticationToken)) {
			return true;
		} else {
			return false;
		}
	}
	
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
    	if(!isLoggedIn()) {
    		// not logged in
	    	String jwtToken = jwtTokenService.readTokenFromRequest(request);
			if (StringUtils.isNotBlank(jwtToken)) { 
				// have jwt cookie
				JwtBody jwtBody = jwtTokenService.decodeAndVerifyToken(jwtToken);
				if (jwtBody != null) {
					// token is valid
					String username = jwtBody.getUsername();
					UserDetails userDetails = userDetailsService.loadUserByUsername(username);
					UsernamePasswordAuthenticationToken authResult = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					authResult.setDetails(authenticationDetailsSource.buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authResult);
				}
	    	}
    	}
    	
		if (isLoggedIn()) {
			jwtTokenService.writeTokenToResponse(response, SecurityContextHolder.getContext().getAuthentication());
		}
    	
    	filterChain.doFilter(request, response);
    }

	
	public JwtTokenService getJwtTokenService() {
		return jwtTokenService;
	}

	public void setJwtTokenService(JwtTokenService jwtTokenService) {
		this.jwtTokenService = jwtTokenService;
	}

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}
}
