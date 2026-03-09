package com.fido.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.fido.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);
}