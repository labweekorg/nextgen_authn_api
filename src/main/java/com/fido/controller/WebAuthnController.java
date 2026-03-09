package com.fido.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fido.dto.LoginOptionsRequest;
import com.fido.dto.LoginVerifyRequest;
import com.fido.dto.RegistrationOptionsRequest;
import com.fido.dto.RegistrationVerifyRequest;
import com.fido.service.WebAuthnService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/webauthn")
@RequiredArgsConstructor
public class WebAuthnController {
	private final WebAuthnService webAuthnService;

	@PostMapping("/register/options")
	public Map<String, Object> registerOptions(@RequestBody RegistrationOptionsRequest request) {
		return webAuthnService.generateRegistrationOptions(request);
	}

	@PostMapping("/register/verify")
	public Map<String, Object> verifyRegistration(@RequestBody RegistrationVerifyRequest request) {
		return webAuthnService.verifyRegistration(request);
	}

	@PostMapping("/login/options")
	public Map<String, Object> loginOptions(@RequestBody LoginOptionsRequest request) {
		return webAuthnService.generateLoginOptions(request);
	}

	@PostMapping("/login/verify")
	public Map<String, Object> verifyLogin(@RequestBody LoginVerifyRequest request) {
		return webAuthnService.verifyLogin(request);
	}
}