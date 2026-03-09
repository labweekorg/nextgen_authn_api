package com.fido.dto;

import java.util.Map;

import lombok.Data;

@Data
public class LoginVerifyRequest {
	private String id;
	private String rawId;
	private String type;
	private Map<String, Object> response;
}