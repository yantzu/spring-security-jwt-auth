# spring-security-jwt-auth
	@Bean
	public JwtTokenService jwtTokenService() throws Exception {
		String signerConfig = getApplicationContext().getEnvironment().getProperty("jwt.signer.keys");

		TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>() {
		};
		ObjectMapper jsonMapper = new ObjectMapper();
		Map<String, String> signerVerifierKeys = jsonMapper.readValue(signerConfig, typeRef);

		JwtTokenService jwtTokenService = new JwtTokenService();
		jwtTokenService.setSignerVerifierKeys(signerVerifierKeys);
		return jwtTokenService;
	}

	@Bean
	public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() throws Exception {
		JwtAuthenticationProcessingFilter authFilter = new JwtAuthenticationProcessingFilter();
		authFilter.setJwtTokenService(getBeanOrThrowException(JwtTokenService.class));
		authFilter.setUserDetailsService(getBeanOrThrowException(UserDetailsService.class));
		return authFilter;
	}
    
	@Bean
	public JwtAuthenticationSuccessEventListener jwtAuthenticationSuccessEventListener() {
		JwtAuthenticationSuccessEventListener listener = new JwtAuthenticationSuccessEventListener();
		listener.setJwtTokenService(getBeanOrThrowException(JwtTokenService.class));
		return listener;
	}
	
	@Bean
	public JwtLogoutHandler jwtLogoutHandler() {
		JwtLogoutHandler handler = new JwtLogoutHandler();
		handler.setJwtTokenService(getBeanOrThrowException(JwtTokenService.class));
		return handler;
	}
  
  	private <T> T getBeanOrThrowException(Class<T> type) {
		T bean = getBeanOrNull(type);
		if (bean == null) {
			throw new IllegalStateException("no bean with type " + type);
		}
		return bean;
	}
    
    private <T> T getBeanOrNull(Class<T> type) {
        String[] userDetailsBeanNames = getApplicationContext().getBeanNamesForType(type);
        if (userDetailsBeanNames.length != 1) {
            return null;
        }

        return getApplicationContext().getBean(userDetailsBeanNames[0], type);
    }
