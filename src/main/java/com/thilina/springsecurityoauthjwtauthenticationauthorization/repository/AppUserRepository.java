package com.thilina.springsecurityoauthjwtauthenticationauthorization.repository;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.AppUser;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface AppUserRepository extends CrudRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
}
