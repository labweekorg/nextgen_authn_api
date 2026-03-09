package com.fido.dto;

import java.util.Map;

import lombok.Data;

@Data
public class RegistrationVerifyRequest {
	private String id;       // credential ID (Base64URL)
	private String rawId;    // raw credential ID (Base64URL)
	private String type;     // always "public-key"
	private String username; // which user is registering (sent by frontend, not part of WebAuthn spec)
	private Map<String, Object> response; // contains clientDataJSON, attestationObject
}