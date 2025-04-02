package br.com.fiap.api_security.repository;

import br.com.fiap.api_security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserRepository  extends JpaRepository<User, UUID> {
    UserDetails findByUsername(String username);
}
