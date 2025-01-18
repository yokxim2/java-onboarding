package org.example.javaonboarding.domain.user.dao;

import org.example.javaonboarding.domain.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
