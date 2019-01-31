package com.github.yantzu.springsecurity.jwt;

public class JwtBody {
	private String username;
	private String signer;
	private Long lifetime;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getSigner() {
		return signer;
	}

	public void setSigner(String signer) {
		this.signer = signer;
	}

	public Long getLifetime() {
		return lifetime;
	}

	public void setLifetime(Long lifetime) {
		this.lifetime = lifetime;
	}

}
