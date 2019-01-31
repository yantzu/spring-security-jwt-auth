package com.github.yantzu.springsecurity.jwt;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignerVerifier;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtTokenService implements InitializingBean {
	
	private static final Logger LOG = LoggerFactory.getLogger(JwtTokenService.class);
	
	private String tokenCookieName = "JWT-SESSION-TOKEN";
	private Map<String, String> signerVerifierKeys;
	
	
	private Map<String, SignerVerifier> signerVerifiers = new HashMap<String, SignerVerifier>();
	private ObjectMapper jsonMapper = new ObjectMapper();

	@Override
	public void afterPropertiesSet() throws Exception {
		for (Entry<String, String> key : signerVerifierKeys.entrySet()) {
			signerVerifiers.put(key.getKey(), new MacSigner(key.getValue().getBytes()));
		}
	}
	
	public String encodeToToken(JwtBody jwtBody) throws JsonProcessingException {
		Entry<String, SignerVerifier> signerVerifier = randomSigner();
		jwtBody.setSigner(signerVerifier.getKey());
		String jwtBodyString = jsonMapper.writeValueAsString(jwtBody);
		return JwtHelper.encode(jwtBodyString, signerVerifier.getValue()).getEncoded();
	}
    
	public JwtBody decodeAndVerifyToken(String jwtToken) {
		Jwt jwt = JwtHelper.decode(jwtToken);
		try {
			JwtBody jwtBody = jsonMapper.readValue(jwt.getClaims(), JwtBody.class);
			SignerVerifier signerVerifier = signerVerifiers.get(jwtBody.getSigner());
			JwtHelper.decodeAndVerify(jwtToken, signerVerifier);
			if (jwtBody.getLifetime() > System.currentTimeMillis()) {
				return jwtBody;
			} else {
				return null;
			}
		} catch (InvalidSignatureException ise) {
			LOG.warn("InvalidSignatureException:" + ise.getMessage());
			return null;
		} catch (JsonParseException jpe) {
			LOG.warn("JsonParseException:" + jpe.getMessage());
			return null;
		} catch (JsonMappingException jme) {
			LOG.warn("JsonMappingException:" + jme.getMessage());
			return null;
		} catch (IOException ioe) {
			LOG.warn("IOException:" + ioe.getMessage());
			return null;
		}
	}
    
	public String readTokenFromRequest(HttpServletRequest request) {
		for (Cookie cookie : request.getCookies()) {
			if (cookie.getName().equals(tokenCookieName)) {
				return cookie.getValue();
			}
		}
		return null;
	}
	
	public void writeTokenToResponse(HttpServletResponse response, Authentication authentication) {
		if (authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof AnonymousAuthenticationToken)) {
			try {
				JwtBody jwtBody = new JwtBody();
				UserDetails userDetails = (UserDetails) authentication.getPrincipal();
				jwtBody.setUsername(userDetails.getUsername());
				jwtBody.setLifetime(System.currentTimeMillis() + 30 * 60 * 1000);
				String jwtToken = encodeToToken(jwtBody);
				writeTokenToResponse(response, jwtToken);
			} catch (JsonProcessingException jpe) {
				LOG.warn("JsonParseException:" + jpe.getMessage());
			}
		}
	}
	
	public void writeTokenToResponse(HttpServletResponse response, String jwtToken) {
		if (!response.isCommitted()) {
			Cookie cookie = new Cookie(tokenCookieName, jwtToken);
			if (StringUtils.isBlank(jwtToken)) {
				cookie.setMaxAge(0);
			}
			response.addCookie(cookie);
		}
	}
	
	private Entry<String, SignerVerifier> randomSigner() {
		int random = new Random().nextInt(signerVerifiers.size());
		int i = 0;
		for (Entry<String, SignerVerifier> signer : signerVerifiers.entrySet()) {
			if (i >= random) {
				return signer;
			} else {
				i++;
			}
		}
		LOG.error("random signer failed, must be a bug here");
		return null;
	}

	public String getTokenCookieName() {
		return tokenCookieName;
	}

	public void setTokenCookieName(String tokenCookieName) {
		this.tokenCookieName = tokenCookieName;
	}

	public Map<String, String> getSignerVerifierKeys() {
		return signerVerifierKeys;
	}

	public void setSignerVerifierKeys(Map<String, String> signerVerifierKeys) {
		this.signerVerifierKeys = signerVerifierKeys;
	}

}
