package com.thilina.springsecurityoauthjwtauthenticationauthorization.service;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.dto.SignUpRequest;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.enums.RoleName;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.enums.security.SocialProvider;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.AppUser;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.Role;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty.OAuth2UserInfo;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty.OAuth2UserInfoFactory;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty.SecurityUser;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.repository.AppUserRepository;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.repository.RoleRepository;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.utils.AuthenticationHelper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService{

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @Override
    public SecurityUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);
        if (!StringUtils.hasLength(oAuth2UserInfo.getName())) {
            throw new RuntimeException("Name not found from OAuth2 provider");
        } else if (!StringUtils.hasLength(oAuth2UserInfo.getEmail())) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }
        SignUpRequest userDetails = toUserRegistrationObject(registrationId, oAuth2UserInfo);
        Optional<AppUser> optionalAppUser = appUserRepository.findByEmail(oAuth2UserInfo.getEmail());
        AppUser user= null;
        if (optionalAppUser.isPresent()) {
            user= optionalAppUser.get();
            if (!user.getProvider().equals(registrationId) && !user.getProvider().equals(SocialProvider.LOCAL.getProviderType())) {
                throw new RuntimeException(
                        "Looks like you're signed up with " + user.getProviderUserId() + " account. Please use your " + user.getProviderUserId() + " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(userDetails);
        }
        return user != null ?new SecurityUser(user) :null;
    }

    @SneakyThrows
    public AppUser registerNewUser(final SignUpRequest signUpRequest){
        if (signUpRequest.getUserID() != null && appUserRepository.existsById(signUpRequest.getUserID())) {
            throw new RuntimeException("User with User id " + signUpRequest.getUserID() + " already exist");
        } else if (appUserRepository.findByEmail(signUpRequest.getEmail()).isPresent()) {
            throw new RuntimeException("User with email id " + signUpRequest.getEmail() + " already exist");
        }
        AppUser user = AppUser.builder()
                .displayName(signUpRequest.getDisplayName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .providerUserId(signUpRequest.getProviderUserId())
                .provider(signUpRequest.getSocialProvider().getProviderType())
                .enabled(true)
                .roles(new HashSet<>())
                .build();
        
        final HashSet<Role> roles = new HashSet<Role>();
        Role role = roleRepository.findByName(RoleName.ROLE_USER.name());
        role.setAppUsers(new HashSet<>());
        roles.add(role);
        user.grantRoles(roles);
        user = appUserRepository.save(user);
        return user;
    }

    private AppUser updateExistingUser(AppUser existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setDisplayName(oAuth2UserInfo.getName());
        return appUserRepository.save(existingUser);
    }

    private SignUpRequest toUserRegistrationObject(String registrationId, OAuth2UserInfo oAuth2UserInfo) {
        return SignUpRequest.builder()
                .providerUserId(oAuth2UserInfo.getId())
                .displayName(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .socialProvider(AuthenticationHelper.toSocialProvider(registrationId))
                .password(oAuth2UserInfo.getId())
                .build();
    }

}
