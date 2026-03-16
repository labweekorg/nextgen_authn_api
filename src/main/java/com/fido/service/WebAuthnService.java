package com.fido.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.fido.config.WebAuthnConfig;
import com.fido.dto.LoginOptionsRequest;
import com.fido.dto.LoginVerifyRequest;
import com.fido.dto.RegistrationOptionsRequest;
import com.fido.dto.RegistrationVerifyRequest;
import com.fido.entity.Credential;
import com.fido.entity.User;
import com.fido.repository.CredentialRepository;
import com.fido.repository.UserRepository;
import com.fido.util.ChallengeStore;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnService {

	// --- Injected by Spring via constructor (RequiredArgsConstructor) ---
	private final UserRepository userRepository;
	private final CredentialRepository credentialRepository;
	private final ChallengeStore challengeStore;
	private final WebAuthnManager webAuthnManager;
	private final WebAuthnConfig webAuthnConfig;

	// --- Initialized manually (not Spring beans) ---
	private ObjectConverter objectConverter;
	private AttestedCredentialDataConverter attestedCredentialDataConverter;

	@PostConstruct
	public void init() {
		this.objectConverter = new ObjectConverter();
		this.attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
	}

	// ═══════════════════════════════════════════════════════════════
	// FIDO2 FLOW OVERVIEW:
	//
	// REGISTRATION (one-time setup per device):
	//   1. Browser calls /register/options → server returns challenge
	//   2. Browser calls navigator.credentials.create() →
	//      device generates KEY PAIR:
	//        - PRIVATE KEY stays on the device (never leaves)
	//        - PUBLIC KEY sent to server in attestationObject
	//   3. Browser calls /register/verify → server validates &
	//      stores the PUBLIC KEY in the credentials table
	//
	// AUTHENTICATION (every login):
	//   1. Browser calls /login/options → server returns challenge
	//   2. Browser calls navigator.credentials.get() →
	//      device signs the challenge with the PRIVATE KEY
	//      (triggered by biometric/passkey/faceID/PIN)
	//   3. Browser calls /login/verify → server validates the
	//      signature using the stored PUBLIC KEY
	//
	// Supported authenticator types:
	//   - biometric=true  → platform authenticator (fingerprint, Face ID, Windows Hello)
	//   - biometric=false → cross-platform authenticator (YubiKey, security key)
	//   - Passkeys        → discoverable credentials stored in iCloud/Google/Microsoft
	// ═══════════════════════════════════════════════════════════════

	// ──────────────────────────────────────────────
	// 1. Registration: generate options (challenge)
	// ──────────────────────────────────────────────
	public Map<String, Object> generateRegistrationOptions(RegistrationOptionsRequest request) {
		String username = request.getUsername();
		String displayName = request.getDisplayName() != null ? request.getDisplayName() : username;
		boolean biometric = request.isBiometric();

		// Create or find the user
		User user = userRepository.findByUsername(username).orElseGet(() -> {
			String userHandle = Base64.getUrlEncoder().withoutPadding()
					.encodeToString(UUID.randomUUID().toString().getBytes());
			return userRepository.save(User.builder()
					.username(username)
					.displayName(displayName)
					.userHandle(userHandle)
					.build());
		});

		// Generate a cryptographically random challenge (32 bytes)
		byte[] challengeBytes = new byte[32];
		new SecureRandom().nextBytes(challengeBytes);
		String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
		challengeStore.store(username, challenge);
		challengeStore.store(username + ":authType", biometric ? "platform" : "cross-platform");

		// Relying Party info
		Map<String, Object> rp = new HashMap<>();
		rp.put("name", webAuthnConfig.getRpName());
		rp.put("id", webAuthnConfig.getRpId());

		// User info — the "id" is the user handle (opaque identifier, NOT the username)
		Map<String, Object> userInfo = new HashMap<>();
		userInfo.put("id", user.getUserHandle());
		userInfo.put("name", user.getUsername());
		userInfo.put("displayName", user.getDisplayName());

		// Supported algorithms
		List<Map<String, Object>> pubKeyCredParams = List.of(
				Map.of("type", "public-key", "alg", -7),   // ES256 (preferred)
				Map.of("type", "public-key", "alg", -257)  // RS256 (fallback)
		);

		// Authenticator selection — controlled by the biometric flag
		Map<String, Object> authenticatorSelection = new HashMap<>();
		if (biometric) {
			// Platform authenticator = built-in biometric (fingerprint, Face ID, Windows Hello)
			// Also covers passkeys (discoverable credentials)
			authenticatorSelection.put("authenticatorAttachment", "platform");
			authenticatorSelection.put("userVerification", "required");
			authenticatorSelection.put("residentKey", "required");
			authenticatorSelection.put("requireResidentKey", true);
		} else {
			// Cross-platform authenticator = external security key (YubiKey, Titan, etc.)
			authenticatorSelection.put("authenticatorAttachment", "cross-platform");
			authenticatorSelection.put("userVerification", "preferred");
			authenticatorSelection.put("residentKey", "preferred");
		}

		// Exclude existing credentials to prevent re-registration of same authenticator
		List<Map<String, Object>> excludeCredentials = credentialRepository.findByUser(user).stream()
				.map(c -> Map.<String, Object>of(
						"type", "public-key",
						"id", c.getCredentialId()
				))
				.collect(Collectors.toList());

		// Build the PublicKeyCredentialCreationOptions
		Map<String, Object> options = new HashMap<>();
		options.put("challenge", challenge);
		options.put("rp", rp);
		options.put("user", userInfo);
		options.put("pubKeyCredParams", pubKeyCredParams);
		options.put("authenticatorSelection", authenticatorSelection);
		options.put("timeout", 60000);
		options.put("attestation", "direct");
		options.put("biometric", biometric);
		if (!excludeCredentials.isEmpty()) {
			options.put("excludeCredentials", excludeCredentials);
		}

		log.info("Registration options generated for user: {}, biometric: {}", username, biometric);
		return options;
	}

	// ──────────────────────────────────────────────
	// 2. Registration: verify the credential
	//    - Validates attestation using webauthn4j
	//    - Extracts and stores the PUBLIC KEY
	//    - The PRIVATE KEY remains on the user's device
	// ──────────────────────────────────────────────
	public Map<String, Object> verifyRegistration(RegistrationVerifyRequest request) {
		Map<String, Object> result = new HashMap<>();

		try {
			String credentialId = request.getId();
			String username = request.getUsername(); // top-level field, not inside response
			Map<String, Object> response = request.getResponse();

			if (credentialId == null || response == null) {
				result.put("status", "error");
				result.put("message", "Missing credential id or response");
				return result;
			}

			if (username == null || username.isBlank()) {
				result.put("status", "error");
				result.put("message", "Username is required for registration verification");
				return result;
			}

			String clientDataJSON = (String) response.get("clientDataJSON");
			String attestationObject = (String) response.get("attestationObject");

			if (clientDataJSON == null || attestationObject == null) {
				result.put("status", "error");
				result.put("message", "Missing clientDataJSON or attestationObject in response");
				return result;
			}

			// Validate we have a pending challenge for this user
			String storedChallenge = challengeStore.get(username);
			if (storedChallenge == null) {
				result.put("status", "error");
				result.put("message", "No pending registration challenge found for user: " + username);
				return result;
			}

			// Find the user
			Optional<User> userOpt = userRepository.findByUsername(username);
			if (userOpt.isEmpty()) {
				result.put("status", "error");
				result.put("message", "User not found: " + username);
				return result;
			}
			User user = userOpt.get();

			// Check if credential already exists
			if (credentialRepository.findByCredentialId(credentialId).isPresent()) {
				result.put("status", "error");
				result.put("message", "Credential already registered");
				return result;
			}

			// ── webauthn4j verification ──
			// Decode the Base64URL-encoded data from the browser
			log.info("Decoding clientDataJSON: {}", clientDataJSON.length() > 20 ? clientDataJSON.substring(0, 10) + "..." + clientDataJSON.substring(clientDataJSON.length() - 10) : clientDataJSON);
			log.info("Decoding attestationObject: {}", attestationObject.length() > 20 ? attestationObject.substring(0, 10) + "..." + attestationObject.substring(attestationObject.length() - 10) : attestationObject);
			log.info("Decoding storedChallenge: {}", storedChallenge.length() > 20 ? storedChallenge.substring(0, 10) + "..." + storedChallenge.substring(storedChallenge.length() - 10) : storedChallenge);
			byte[] clientDataJSONBytes = decodeBase64UrlSafe(clientDataJSON);
			byte[] attestationObjectBytes = decodeBase64UrlSafe(attestationObject);
			byte[] challengeBytes = decodeBase64UrlSafe(storedChallenge);

			// Build ServerProperty with the stored challenge
			ServerProperty serverProperty = new ServerProperty(
					new Origin(webAuthnConfig.getOrigin()),
					webAuthnConfig.getRpId(),
					new DefaultChallenge(challengeBytes),
					null // tokenBindingId
			);

			// Parse and validate the attestation using webauthn4j
			RegistrationRequest registrationRequest = new RegistrationRequest(
					attestationObjectBytes,
					clientDataJSONBytes
			);
			RegistrationParameters registrationParameters = new RegistrationParameters(
					serverProperty,
					null, // pubKeyCredParams — null accepts any algorithm
					true, // userVerificationRequired
					false // userPresenceRequired
			);

			RegistrationData registrationData = webAuthnManager.parse(registrationRequest);
			webAuthnManager.validate(registrationData, registrationParameters);

			// ── Extract the PUBLIC KEY from the verified attestation ──
			// The device generated a key pair:
			//   - Private key → stored securely on the device (biometric/passkey protected)
			//   - Public key  → extracted here and stored in our DB
			AttestedCredentialData attestedCredData = registrationData
					.getAttestationObject()
					.getAuthenticatorData()
					.getAttestedCredentialData();

			if (attestedCredData == null) {
				result.put("status", "error");
				result.put("message", "No attested credential data found in attestation");
				return result;
			}

			// Serialize the attested credential data (includes credentialId + public key)
			byte[] serializedAttestedCredData = attestedCredentialDataConverter.convert(attestedCredData);

			// Serialize just the COSE public key for storage
			COSEKey coseKey = attestedCredData.getCOSEKey();
			byte[] serializedPublicKey = objectConverter.getCborConverter().writeValueAsBytes(coseKey);

			String aaguid = attestedCredData.getAaguid().toString();
			long signCount = registrationData.getAttestationObject()
					.getAuthenticatorData().getSignCount();

			// Determine authenticator type from the biometric flag set during /register/options
			// AAGUID identifies the authenticator MODEL (e.g., YubiKey 5, Touch ID), NOT whether
			// it's platform or cross-platform. For example:
			//   - YubiKey has non-zero AAGUID but is "cross-platform"
			//   - Touch ID with "none" attestation has all-zeros AAGUID but is "platform"
			// So we use the biometric flag from the registration options step instead.
			String storedAuthType = challengeStore.get(username + ":authType");
			String authenticatorType = "platform".equals(storedAuthType) ? "platform" : "cross-platform";

			// Save the credential (public key) to the database
			Credential credential = Credential.builder()
					.credentialId(credentialId)
					.publicKey(serializedPublicKey)
					.attestedCredentialData(serializedAttestedCredData)
					.aaguid(aaguid)
					.signCount(signCount)
					.authenticatorType(authenticatorType)
					.user(user)
					.build();
			credentialRepository.save(credential);

			// Clean up the challenge (one-time use)
			challengeStore.remove(username);
			challengeStore.remove(username + ":authType");

			result.put("status", "ok");
			result.put("message", "Registration successful — public key stored, private key on your device");
			result.put("credentialId", credentialId);
			result.put("username", username);
			result.put("authenticatorType", authenticatorType);
			result.put("aaguid", aaguid);
			result.put("verified", true);

			log.info("FIDO2 registration successful for user: {}, type: {}, aaguid: {}",
					username, authenticatorType, aaguid);

		} catch (Exception e) {
			log.error("Registration verification failed", e);
			result.put("status", "error");
			result.put("verified", false);
			result.put("message", "Registration verification failed: " + e.getMessage());
		}

		return result;
	}

	// ──────────────────────────────────────────────
	// 3. Login: generate options (challenge)
	//    Supports both:
	//    - Username-based login (user provides username)
	//    - Discoverable/passkey login (username is null,
	//      device discovers the credential)
	// ──────────────────────────────────────────────
	public Map<String, Object> generateLoginOptions(LoginOptionsRequest request) {
		String username = request.getUsername();
		Map<String, Object> result = new HashMap<>();

		// Generate a new challenge
		byte[] challengeBytes = new byte[32];
		new SecureRandom().nextBytes(challengeBytes);
		String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

		if (username != null && !username.isBlank()) {
			// ── Username-based login ──
			Optional<User> userOpt = userRepository.findByUsername(username);
			if (userOpt.isEmpty()) {
				result.put("status", "error");
				result.put("message", "User not found: " + username);
				return result;
			}

			User user = userOpt.get();
			List<Credential> credentials = credentialRepository.findByUser(user);

			if (credentials.isEmpty()) {
				result.put("status", "error");
				result.put("message", "No credentials registered for user: " + username);
				return result;
			}

			challengeStore.store(username, challenge);

			// Build the allowCredentials list (tells the browser which credentials to use)
			List<Map<String, Object>> allowCredentials = credentials.stream()
					.map(c -> {
						Map<String, Object> cred = new HashMap<>();
						cred.put("type", "public-key");
						cred.put("id", c.getCredentialId());
						if ("platform".equals(c.getAuthenticatorType())) {
							cred.put("transports", List.of("internal")); // biometric
						} else {
							cred.put("transports", List.of("usb", "ble", "nfc")); // security key
						}
						return cred;
					})
					.collect(Collectors.toList());

			result.put("allowCredentials", allowCredentials);
		} else {
			// ── Discoverable / Passkey login (no username needed) ──
			// The device will discover available credentials for this rpId
			// Store challenge with a temp key; will be resolved on verify via credentialId
			challengeStore.store("__discoverable__", challenge);
		}

		result.put("challenge", challenge);
		result.put("rpId", webAuthnConfig.getRpId());
		result.put("userVerification", "required");
		result.put("timeout", 60000);

		log.info("Login options generated, username: {}", username != null ? username : "discoverable");
		return result;
	}

	// ──────────────────────────────────────────────
	// 4. Login: verify the assertion
	//    - Uses webauthn4j to cryptographically verify
	//      that the device signed the challenge with
	//      the PRIVATE KEY matching our stored PUBLIC KEY
	//    - This is how biometric/passkey/faceID authentication works
	// ──────────────────────────────────────────────
	public Map<String, Object> verifyLogin(LoginVerifyRequest request) {
		Map<String, Object> result = new HashMap<>();

		try {
			String credentialId = request.getId();
			Map<String, Object> response = request.getResponse();

			if (credentialId == null || response == null) {
				result.put("status", "error");
				result.put("message", "Missing credential id or response");
				return result;
			}

			// Find the stored credential (contains the PUBLIC KEY)
			Optional<Credential> credOpt = credentialRepository.findByCredentialId(credentialId);
			if (credOpt.isEmpty()) {
				result.put("status", "error");
				result.put("message", "Credential not found: " + credentialId);
				return result;
			}
			Credential credential = credOpt.get();
			User user = credential.getUser();

			// Extract assertion data from browser response
			String clientDataJSON = (String) response.get("clientDataJSON");
			String authenticatorData = (String) response.get("authenticatorData");
			String signature = (String) response.get("signature");
			String userHandleStr = (String) response.get("userHandle"); // may be null for non-discoverable

			if (clientDataJSON == null || authenticatorData == null || signature == null) {
				result.put("status", "error");
				result.put("message", "Missing clientDataJSON, authenticatorData, or signature in response");
				return result;
			}

			// Retrieve the stored challenge
			// Try username-based first, then discoverable
			String storedChallenge = challengeStore.get(user.getUsername());
			if (storedChallenge == null) {
				storedChallenge = challengeStore.get("__discoverable__");
			}
			if (storedChallenge == null) {
				result.put("status", "error");
				result.put("message", "No pending login challenge found");
				return result;
			}

			// ── webauthn4j assertion verification ──
			// Use credentialId as a string (not decoded)
			byte[] clientDataJSONBytes = decodeBase64UrlSafe(clientDataJSON);
			byte[] authenticatorDataBytes = decodeBase64UrlSafe(authenticatorData);
			byte[] signatureBytes = decodeBase64UrlSafe(signature);
			byte[] userHandleBytes = (userHandleStr != null && !userHandleStr.isBlank())
					? decodeBase64UrlSafe(userHandleStr)
					: null;

			// Build ServerProperty with the stored challenge
			byte[] challengeBytes = decodeBase64UrlSafe(storedChallenge);
			ServerProperty serverProperty = new ServerProperty(
					new Origin(webAuthnConfig.getOrigin()),
					webAuthnConfig.getRpId(),
					new DefaultChallenge(challengeBytes),
					null
			);

			// Reconstruct the authenticator from stored public key data
			AttestedCredentialData attestedCredData = attestedCredentialDataConverter
					.convert(credential.getAttestedCredentialData());
			Authenticator authenticator = new AuthenticatorImpl(
					attestedCredData,
					null, // attestationStatement
					credential.getSignCount()
			);

			// Build the authentication request
			// webauthn4j AuthenticationRequest constructor:
			// (credentialId, userHandle, authenticatorData, clientDataJSON, signature)
			AuthenticationRequest authenticationRequest = new AuthenticationRequest(
					credential.getCredentialId().getBytes(), // Use credentialId as string bytes
					userHandleBytes,        // userHandle (from device for discoverable flow)
					authenticatorDataBytes,
					clientDataJSONBytes,
					signatureBytes
			);

			AuthenticationParameters authenticationParameters = new AuthenticationParameters(
					serverProperty,
					authenticator,
					null, // allowCredentials
					true, // userVerificationRequired
					false // userPresenceRequired
			);

			// This is the critical step:
			// webauthn4j verifies that the SIGNATURE was created by the PRIVATE KEY
			// that matches the PUBLIC KEY we stored during registration
			AuthenticationData authenticationData = webAuthnManager.parse(authenticationRequest);
			webAuthnManager.validate(authenticationData, authenticationParameters);

			// Update sign count (replay attack protection)
			long newSignCount = authenticationData.getAuthenticatorData().getSignCount();
			credential.setSignCount(newSignCount);
			credentialRepository.save(credential);

			// Clean up challenges
			challengeStore.remove(user.getUsername());
			challengeStore.remove("__discoverable__");

			result.put("status", "ok");
			result.put("message", "Authentication successful");
			result.put("username", user.getUsername());
			result.put("displayName", user.getDisplayName());
			result.put("credentialId", credentialId);
			result.put("authenticatorType", credential.getAuthenticatorType());
			result.put("verified", true);

			log.info("FIDO2 login successful for user: {}, type: {}",
					user.getUsername(), credential.getAuthenticatorType());

		} catch (Exception e) {
			log.error("Login verification failed", e);
			result.put("status", "error");
			result.put("message", "Login verification failed: " + e.getMessage());
		}

		return result;
	}

	/**
	 * Decodes a Base64url string, adding padding if necessary.
	 * This prevents IllegalArgumentException: Last unit does not have enough valid bits.
	 */
	private byte[] decodeBase64UrlSafe(String base64url) {
		if (base64url == null) {
			log.error("decodeBase64UrlSafe: input is null");
			return null;
		}
		int padding = (4 - (base64url.length() % 4)) % 4;
		StringBuilder sb = new StringBuilder(base64url);
		for (int i = 0; i < padding; i++) sb.append('=');
		String padded = sb.toString();
		String preview = base64url.length() > 20 ? base64url.substring(0, 10) + "..." + base64url.substring(base64url.length() - 10) : base64url;
		log.info("Decoding Base64URL: length={}, preview={}", base64url.length(), preview);
		if (base64url.length() < 10) {
			log.warn("Base64URL input is very short: {}", base64url);
		}
		try {
			return Base64.getUrlDecoder().decode(padded);
		} catch (IllegalArgumentException e) {
			log.error("Base64 decode failed for input (length {}): {}", base64url.length(), preview);
			throw new IllegalArgumentException("Base64 decode failed for input (preview): " + preview, e);
		}
	}
}

