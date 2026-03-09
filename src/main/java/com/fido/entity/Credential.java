package com.fido.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "credentials")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Credential {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = false)
	private String credentialId;

	@Lob
	@Column(columnDefinition = "LONGBLOB")
	private byte[] publicKey;

	@Lob
	@Column(columnDefinition = "LONGBLOB")
	private byte[] attestedCredentialData;

	private String aaguid;

	private long signCount;

	private String authenticatorType; // "platform" (biometric) or "cross-platform" (security key)

	@ManyToOne
	@JoinColumn(name = "user_id", nullable = false)
	private User user;
}