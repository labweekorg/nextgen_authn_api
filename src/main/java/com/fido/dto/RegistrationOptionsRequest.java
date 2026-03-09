package com.fido.dto;

import lombok.Data;

@Data
public class RegistrationOptionsRequest {
	private String username;
	private String displayName;
	private boolean biometric; // true = platform authenticator (fingerprint/face), false = cross-platform (security key)
}