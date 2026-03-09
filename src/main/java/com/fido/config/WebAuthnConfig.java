package com.fido.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.webauthn4j.WebAuthnManager;

import lombok.Getter;

@Configuration
@Getter
public class WebAuthnConfig {

	@Value("${webauth.rp-id}")
	private String rpId;

	@Value("${webauth.rp-name}")
	private String rpName;

	@Value("${webauth.origin}")
	private String origin;

	@Bean
	public WebAuthnManager webAuthnManager() {
		return WebAuthnManager.createNonStrictWebAuthnManager();
	}
}