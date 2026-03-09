package com.fido.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.fido.entity.Credential;
import com.fido.entity.User;

public interface CredentialRepository extends JpaRepository<Credential, Long> {
	Optional<Credential> findByCredentialId(String credentialId);

	List<Credential> findByUser(User user);
}