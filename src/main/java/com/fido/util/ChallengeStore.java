package com.fido.util;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

@Component
public class ChallengeStore {

	private static final long CHALLENGE_TTL_SECONDS = 300; // 5 minutes

	private final Map<String, ChallengeEntry> challengeMap = new ConcurrentHashMap<>();

	public void store(String key, String value) {
		challengeMap.put(key, new ChallengeEntry(value, Instant.now()));
	}

	public String get(String key) {
		ChallengeEntry entry = challengeMap.get(key);
		if (entry == null) {
			return null;
		}
		// Check if the challenge has expired
		if (Instant.now().isAfter(entry.createdAt.plusSeconds(CHALLENGE_TTL_SECONDS))) {
			challengeMap.remove(key);
			return null;
		}
		return entry.value;
	}

	public void remove(String key) {
		challengeMap.remove(key);
	}

	private static class ChallengeEntry {
		final String value;
		final Instant createdAt;

		ChallengeEntry(String value, Instant createdAt) {
			this.value = value;
			this.createdAt = createdAt;
		}
	}
}