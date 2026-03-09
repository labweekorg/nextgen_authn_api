package com.fido.authentication;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Integration tests for the FIDO2 WebAuthn biometric/passkey authentication flow.
 *
 * These tests simulate what a real browser + biometric authenticator does:
 * - Generate an ECDSA key pair (simulating the device's Secure Enclave)
 * - Build a valid CBOR attestation object (simulating Face ID / Touch ID / passkey response)
 * - Sign login challenges with the private key (simulating biometric-protected signature)
 * - Verify everything through webauthn4j
 *
 * FIDO2 Key Flow:
 *   Registration: Device generates key pair → PRIVATE KEY stays on device, PUBLIC KEY sent to server
 *   Login: Device signs challenge with PRIVATE KEY → Server verifies using stored PUBLIC KEY
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebAuthnControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	// Shared state across ordered tests
	private static String registrationChallenge;
	private static String loginChallenge;
	private static KeyPair keyPair; // Simulates the device's Secure Enclave key pair
	private static byte[] credentialIdBytes;
	private static String credentialIdBase64;

	private static final String TEST_USERNAME = "test_biometric_user";
	private static final String TEST_DISPLAY_NAME = "Test Biometric User";
	private static final String RP_ID = "localhost";
	private static final String ORIGIN = "http://localhost:3000";

	// ──────────────────────────────────────────────────────────────
	// TEST 1: Registration Options (biometric)
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(1)
	@DisplayName("Step 1: Registration options - biometric (fingerprint/Face ID)")
	void testRegisterOptionsBiometric() throws Exception {
		String requestJson = "{\"username\":\"" + TEST_USERNAME + "\","
				+ "\"displayName\":\"" + TEST_DISPLAY_NAME + "\","
				+ "\"biometric\":true}";

		MvcResult result = mockMvc.perform(post("/webauthn/register/options")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.challenge").exists())
				.andExpect(jsonPath("$.rp.id").value(RP_ID))
				.andExpect(jsonPath("$.user.name").value(TEST_USERNAME))
				.andExpect(jsonPath("$.user.displayName").value(TEST_DISPLAY_NAME))
				.andExpect(jsonPath("$.authenticatorSelection.authenticatorAttachment").value("platform"))
				.andExpect(jsonPath("$.authenticatorSelection.userVerification").value("required"))
				.andExpect(jsonPath("$.authenticatorSelection.residentKey").value("required"))
				.andExpect(jsonPath("$.biometric").value(true))
				.andExpect(jsonPath("$.attestation").value("direct"))
				.andReturn();

		JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
		registrationChallenge = responseJson.get("challenge").asText();
		System.out.println("✅ Test 1 PASSED: Registration options (biometric) - challenge: " + registrationChallenge);
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 2: Registration Verify (webauthn4j validates attestation)
	// Simulates: Device generates key pair via biometric,
	//            sends public key + attestation to server
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(2)
	@DisplayName("Step 2: Registration verify - device creates key pair, server stores public key")
	void testVerifyRegistration() throws Exception {
		// 1. Generate an ECDSA P-256 key pair (simulates device's Secure Enclave)
		//    PRIVATE KEY = stays on device (protected by biometric)
		//    PUBLIC KEY  = sent to server in attestation
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(new ECGenParameterSpec("secp256r1"));
		keyPair = keyGen.generateKeyPair();

		// 2. Generate a random credential ID (simulates authenticator assigning an ID)
		credentialIdBytes = new byte[32];
		new java.security.SecureRandom().nextBytes(credentialIdBytes);
		credentialIdBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialIdBytes);

		// 3. Build clientDataJSON (what the browser sends)
		String clientDataJsonRaw = "{\"type\":\"webauthn.create\","
				+ "\"challenge\":\"" + registrationChallenge + "\","
				+ "\"origin\":\"" + ORIGIN + "\","
				+ "\"crossOrigin\":false}";
		byte[] clientDataJSONBytes = clientDataJsonRaw.getBytes();
		String clientDataBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(clientDataJSONBytes);

		// 4. Build a valid CBOR attestation object with the public key
		byte[] attestationObjectBytes = buildAttestationObject(keyPair, credentialIdBytes);
		String attestationBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(attestationObjectBytes);

		// 5. Send to server (username at top level, not inside response)
		String requestJson = "{\"id\":\"" + credentialIdBase64 + "\","
				+ "\"rawId\":\"" + credentialIdBase64 + "\","
				+ "\"type\":\"public-key\","
				+ "\"username\":\"" + TEST_USERNAME + "\","
				+ "\"response\":{"
				+ "\"clientDataJSON\":\"" + clientDataBase64 + "\","
				+ "\"attestationObject\":\"" + attestationBase64 + "\""
				+ "}}";

		mockMvc.perform(post("/webauthn/register/verify")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("ok"))
				.andExpect(jsonPath("$.message").exists())
				.andExpect(jsonPath("$.credentialId").value(credentialIdBase64))
				.andExpect(jsonPath("$.username").value(TEST_USERNAME))
				.andExpect(jsonPath("$.aaguid").exists());

		System.out.println("✅ Test 2 PASSED: Registration verify - public key stored in DB, private key on device");
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 3: Login Options (username-based)
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(3)
	@DisplayName("Step 3: Login options - returns challenge + allowCredentials for registered user")
	void testLoginOptions() throws Exception {
		String requestJson = "{\"username\":\"" + TEST_USERNAME + "\"}";

		MvcResult result = mockMvc.perform(post("/webauthn/login/options")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.challenge").exists())
				.andExpect(jsonPath("$.rpId").value(RP_ID))
				.andExpect(jsonPath("$.allowCredentials").isArray())
				.andExpect(jsonPath("$.allowCredentials[0].type").value("public-key"))
				.andExpect(jsonPath("$.allowCredentials[0].id").value(credentialIdBase64))
				.andExpect(jsonPath("$.userVerification").value("required"))
				.andReturn();

		JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
		loginChallenge = responseJson.get("challenge").asText();
		System.out.println("✅ Test 3 PASSED: Login options - challenge: " + loginChallenge);
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 4: Login Verify (webauthn4j verifies signature)
	// Simulates: Device signs challenge with private key (via biometric),
	//            server verifies signature using stored public key
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(4)
	@DisplayName("Step 4: Login verify - device signs with private key, server verifies with public key")
	void testVerifyLogin() throws Exception {
		// 1. Build clientDataJSON for login
		String clientDataJsonRaw = "{\"type\":\"webauthn.get\","
				+ "\"challenge\":\"" + loginChallenge + "\","
				+ "\"origin\":\"" + ORIGIN + "\","
				+ "\"crossOrigin\":false}";
		byte[] clientDataJSONBytes = clientDataJsonRaw.getBytes();
		String clientDataBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(clientDataJSONBytes);

		// 2. Build authenticatorData (rpIdHash + flags + signCount)
		byte[] rpIdHash = MessageDigest.getInstance("SHA-256").digest(RP_ID.getBytes());
		byte flags = 0x05; // UP (bit 0) + UV (bit 2) = user present + user verified (biometric)
		int signCount = 1;
		ByteBuffer authDataBuffer = ByteBuffer.allocate(37);
		authDataBuffer.put(rpIdHash);    // 32 bytes
		authDataBuffer.put(flags);       // 1 byte
		authDataBuffer.putInt(signCount); // 4 bytes
		byte[] authenticatorDataBytes = authDataBuffer.array();
		String authenticatorDataBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(authenticatorDataBytes);

		// 3. Sign: authenticatorData + SHA-256(clientDataJSON)
		//    This is what the biometric authenticator does with the PRIVATE KEY
		byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJSONBytes);
		byte[] signedData = new byte[authenticatorDataBytes.length + clientDataHash.length];
		System.arraycopy(authenticatorDataBytes, 0, signedData, 0, authenticatorDataBytes.length);
		System.arraycopy(clientDataHash, 0, signedData, authenticatorDataBytes.length, clientDataHash.length);

		Signature sig = Signature.getInstance("SHA256withECDSA");
		sig.initSign(keyPair.getPrivate());
		sig.update(signedData);
		byte[] signatureBytes = sig.sign();
		String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

		// 4. Send assertion to server
		String requestJson = "{\"id\":\"" + credentialIdBase64 + "\","
				+ "\"rawId\":\"" + credentialIdBase64 + "\","
				+ "\"type\":\"public-key\","
				+ "\"response\":{"
				+ "\"clientDataJSON\":\"" + clientDataBase64 + "\","
				+ "\"authenticatorData\":\"" + authenticatorDataBase64 + "\","
				+ "\"signature\":\"" + signatureBase64 + "\""
				+ "}}";

		mockMvc.perform(post("/webauthn/login/verify")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("ok"))
				.andExpect(jsonPath("$.message").value("Authentication successful"))
				.andExpect(jsonPath("$.username").value(TEST_USERNAME))
				.andExpect(jsonPath("$.credentialId").value(credentialIdBase64));

		System.out.println("✅ Test 4 PASSED: Login verify - biometric signature verified with stored public key");
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 5: Login Options (passkey / discoverable - no username)
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(5)
	@DisplayName("Step 5: Passkey login options - no username (discoverable credential)")
	void testLoginOptionsPasskey() throws Exception {
		String requestJson = "{}";

		mockMvc.perform(post("/webauthn/login/options")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.challenge").exists())
				.andExpect(jsonPath("$.rpId").value(RP_ID))
				.andExpect(jsonPath("$.userVerification").value("required"))
				.andExpect(jsonPath("$.allowCredentials").doesNotExist());

		System.out.println("✅ Test 5 PASSED: Passkey login options (no username, discoverable)");
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 6: Duplicate credential registration should fail
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(6)
	@DisplayName("Step 6: Duplicate credential registration should be rejected")
	void testDuplicateRegistration() throws Exception {
		// Get a new challenge
		String optionsJson = "{\"username\":\"" + TEST_USERNAME + "\","
				+ "\"displayName\":\"" + TEST_DISPLAY_NAME + "\","
				+ "\"biometric\":true}";

		MvcResult optionsResult = mockMvc.perform(post("/webauthn/register/options")
						.contentType(MediaType.APPLICATION_JSON)
						.content(optionsJson))
				.andExpect(status().isOk())
				.andReturn();

		JsonNode optionsResponse = objectMapper.readTree(optionsResult.getResponse().getContentAsString());
		String challenge = optionsResponse.get("challenge").asText();

		// Build clientDataJSON
		String clientDataJsonRaw = "{\"type\":\"webauthn.create\","
				+ "\"challenge\":\"" + challenge + "\","
				+ "\"origin\":\"" + ORIGIN + "\"}";
		String clientDataBase64 = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(clientDataJsonRaw.getBytes());

		// Build attestation with same credential ID
		byte[] attestation = buildAttestationObject(keyPair, credentialIdBytes);
		String attestationBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(attestation);

		String requestJson = "{\"id\":\"" + credentialIdBase64 + "\","
				+ "\"rawId\":\"" + credentialIdBase64 + "\","
				+ "\"type\":\"public-key\","
				+ "\"username\":\"" + TEST_USERNAME + "\","
				+ "\"response\":{"
				+ "\"clientDataJSON\":\"" + clientDataBase64 + "\","
				+ "\"attestationObject\":\"" + attestationBase64 + "\""
				+ "}}";

		mockMvc.perform(post("/webauthn/register/verify")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("error"))
				.andExpect(jsonPath("$.message").value("Credential already registered"));

		System.out.println("✅ Test 6 PASSED: Duplicate credential registration rejected");
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 7: Login with unknown user should fail
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(7)
	@DisplayName("Step 7: Login with unknown user should fail")
	void testLoginUnknownUser() throws Exception {
		mockMvc.perform(post("/webauthn/login/options")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"username\":\"unknown_user\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("error"))
				.andExpect(jsonPath("$.message").value("User not found: unknown_user"));

		System.out.println("✅ Test 7 PASSED: Unknown user login rejected");
	}

	// ──────────────────────────────────────────────────────────────
	// TEST 8: Login with unknown credential should fail
	// ──────────────────────────────────────────────────────────────
	@Test
	@Order(8)
	@DisplayName("Step 8: Login with unknown credential should fail")
	void testLoginUnknownCredential() throws Exception {
		String requestJson = "{\"id\":\"dW5rbm93bi1jcmVk\","
				+ "\"rawId\":\"dW5rbm93bi1jcmVk\","
				+ "\"type\":\"public-key\","
				+ "\"response\":{"
				+ "\"clientDataJSON\":\"dGVzdA\","
				+ "\"authenticatorData\":\"dGVzdA\","
				+ "\"signature\":\"dGVzdA\""
				+ "}}";

		mockMvc.perform(post("/webauthn/login/verify")
						.contentType(MediaType.APPLICATION_JSON)
						.content(requestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("error"))
				.andExpect(jsonPath("$.message").value("Credential not found: dW5rbm93bi1jcmVk"));

		System.out.println("✅ Test 8 PASSED: Unknown credential login rejected");
	}

	// ═══════════════════════════════════════════════════════════════
	// Helper: Build a valid CBOR attestation object
	// This simulates what a real biometric authenticator creates
	// ═══════════════════════════════════════════════════════════════
	private byte[] buildAttestationObject(KeyPair kp, byte[] credId) throws Exception {
		ECPublicKey ecPub = (ECPublicKey) kp.getPublic();

		// Get X and Y coordinates of the EC public key (32 bytes each for P-256)
		byte[] x = toUnsignedFixedLength(ecPub.getW().getAffineX(), 32);
		byte[] y = toUnsignedFixedLength(ecPub.getW().getAffineY(), 32);

		// Build COSE key (CBOR map): {1:2, 3:-7, -1:1, -2:x, -3:y}
		// kty=EC2(2), alg=ES256(-7), crv=P-256(1)
		ByteArrayOutputStream coseKey = new ByteArrayOutputStream();
		coseKey.write(0xA5); // map of 5 items
		coseKey.write(0x01); coseKey.write(0x02);       // 1: 2 (kty: EC2)
		coseKey.write(0x03); coseKey.write(0x26);       // 3: -7 (alg: ES256)
		coseKey.write(0x20); coseKey.write(0x01);       // -1: 1 (crv: P-256)
		coseKey.write(0x21); writeCborBytes(coseKey, x); // -2: x coordinate
		coseKey.write(0x22); writeCborBytes(coseKey, y); // -3: y coordinate
		byte[] coseKeyBytes = coseKey.toByteArray();

		// AAGUID (16 bytes of zeros = software authenticator)
		byte[] aaguid = new byte[16];

		// Build authenticatorData
		byte[] rpIdHash = MessageDigest.getInstance("SHA-256").digest(RP_ID.getBytes());
		byte flags = 0x45; // AT (bit 6) + UV (bit 2) + UP (bit 0) = attested + user verified + user present
		int signCount = 0;

		// credentialIdLength (2 bytes big-endian)
		byte[] credIdLen = new byte[]{(byte) (credId.length >> 8), (byte) (credId.length & 0xFF)};

		ByteArrayOutputStream authData = new ByteArrayOutputStream();
		authData.write(rpIdHash);     // 32 bytes
		authData.write(flags);        // 1 byte
		authData.write(ByteBuffer.allocate(4).putInt(signCount).array()); // 4 bytes
		// attestedCredentialData:
		authData.write(aaguid);       // 16 bytes
		authData.write(credIdLen);    // 2 bytes
		authData.write(credId);       // variable
		authData.write(coseKeyBytes); // variable
		byte[] authenticatorData = authData.toByteArray();

		// Build attestation object: {"fmt":"none","attStmt":{},"authData":<bytes>}
		ByteArrayOutputStream attestObj = new ByteArrayOutputStream();
		attestObj.write(0xA3); // map of 3 items

		// "fmt": "none"
		writeCborString(attestObj, "fmt");
		writeCborString(attestObj, "none");

		// "attStmt": {}
		writeCborString(attestObj, "attStmt");
		attestObj.write(0xA0); // empty map

		// "authData": <bytes>
		writeCborString(attestObj, "authData");
		writeCborBytes(attestObj, authenticatorData);

		return attestObj.toByteArray();
	}

	// Helper: write a CBOR text string
	private void writeCborString(ByteArrayOutputStream out, String s) {
		byte[] bytes = s.getBytes();
		if (bytes.length < 24) {
			out.write(0x60 + bytes.length); // major type 3 (text string)
		} else {
			out.write(0x78); // major type 3, 1-byte length
			out.write(bytes.length);
		}
		out.write(bytes, 0, bytes.length);
	}

	// Helper: write a CBOR byte string
	private void writeCborBytes(ByteArrayOutputStream out, byte[] data) {
		if (data.length < 24) {
			out.write(0x40 + data.length); // major type 2 (byte string)
		} else if (data.length < 256) {
			out.write(0x58); // major type 2, 1-byte length
			out.write(data.length);
		} else {
			out.write(0x59); // major type 2, 2-byte length
			out.write(data.length >> 8);
			out.write(data.length & 0xFF);
		}
		out.write(data, 0, data.length);
	}

	// Helper: convert BigInteger to unsigned fixed-length byte array
	private byte[] toUnsignedFixedLength(BigInteger val, int length) {
		byte[] bytes = val.toByteArray();
		if (bytes.length == length) return bytes;
		byte[] result = new byte[length];
		if (bytes.length > length) {
			// Remove leading zero padding
			System.arraycopy(bytes, bytes.length - length, result, 0, length);
		} else {
			// Pad with leading zeros
			System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
		}
		return result;
	}
}