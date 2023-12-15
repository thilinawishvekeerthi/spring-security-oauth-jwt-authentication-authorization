package com.thilina.springsecurityoauthjwtauthenticationauthorization.repository;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.Role;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<Role, Long> {
    Role findByName(String name);
}
