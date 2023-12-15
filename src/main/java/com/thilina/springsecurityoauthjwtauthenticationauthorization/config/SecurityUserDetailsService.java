package com.thilina.springsecurityoauthjwtauthenticationauthorization.config;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.AppUser;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty.SecurityUser;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SecurityUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository
                .findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("user cannot be found for email :"+ username));
        return (UserDetails) new SecurityUser(appUser);
    }
}
