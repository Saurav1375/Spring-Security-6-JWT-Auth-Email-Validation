package org.example.springsecurity6.repository;

import org.example.springsecurity6.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository  extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(String name);
}
