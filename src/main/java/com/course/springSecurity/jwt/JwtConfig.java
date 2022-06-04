package com.course.springSecurity.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import com.google.common.net.HttpHeaders;

@Component
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {
	
	private String secretKey;
	private String tokenPrefix;
	private Integer tokenExpirationAfterDays;
	
	
	public JwtConfig() {}

	public JwtConfig(String secretKey, String tokenPrefix, Integer tokenExpirationAfterDays) {
		super();
		this.secretKey = secretKey;
		this.tokenPrefix = tokenPrefix;
		this.tokenExpirationAfterDays = tokenExpirationAfterDays;
	}

	@Bean
	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public String getTokenPrefix() {
		return tokenPrefix;
	}

	public void setTokenPrefix(String tokenPrefix) {
		this.tokenPrefix = tokenPrefix;
	}

	public Integer getTokenExpirationAfterDays() {
		return tokenExpirationAfterDays;
	}

	public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
		this.tokenExpirationAfterDays = tokenExpirationAfterDays;
	}

	public String getAuthorizationHeader() {
		return HttpHeaders.AUTHORIZATION;
	}
	
}
