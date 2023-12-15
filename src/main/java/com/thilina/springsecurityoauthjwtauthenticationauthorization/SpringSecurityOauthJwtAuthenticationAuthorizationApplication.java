package com.thilina.springsecurityoauthjwtauthenticationauthorization;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.config.OAuthProperties;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.config.RsaKeyProperties;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.enums.RoleName;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.AppUser;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.Role;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.repository.AppUserRepository;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;

@SpringBootApplication
@EnableConfigurationProperties({OAuthProperties.class, RsaKeyProperties.class})
public class SpringSecurityOauthJwtAuthenticationAuthorizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityOauthJwtAuthenticationAuthorizationApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(RoleRepository roleRepository,
										AppUserRepository appUserRepository,
										PasswordEncoder passwordEncoder){
		return args -> {

			Role userRole = Role.builder()
					.name(RoleName.ROLE_USER.name())
					.appUsers(new HashSet<>())
					.build();

			Role adminRole = Role.builder()
					.name(RoleName.ROLE_ADMIN.name())
					.appUsers(new HashSet<>())
					.build();

			List<Role> userRoles = List.of(userRole, adminRole);
			roleRepository.saveAll(userRoles);

			AppUser appUser = AppUser.builder()
					.displayName("thilina.deshan")
					.email("thilina@gmail.com")
					.password(passwordEncoder.encode("password"))
					.enabled(true)
					.accountNonExpired(true)
					.credentialsNonExpired(true)
					.accountNonLocked(true)
					.roles(new HashSet<>())
					.build();
			appUser.grantRole(userRole);
			appUser.grantRole(adminRole);
			appUserRepository.save(appUser);
		};
	}

}
