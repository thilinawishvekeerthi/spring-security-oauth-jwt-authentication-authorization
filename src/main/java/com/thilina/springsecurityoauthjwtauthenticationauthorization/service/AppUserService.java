package com.thilina.springsecurityoauthjwtauthenticationauthorization.service;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty.SecurityUser;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.util.Map;

public interface AppUserService {
    SecurityUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo);
}
