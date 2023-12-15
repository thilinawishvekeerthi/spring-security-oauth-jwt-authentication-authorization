package com.thilina.springsecurityoauthjwtauthenticationauthorization.model.secuirty;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.AppUser;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;


public class SecurityUser extends User implements OAuth2User, OidcUser {
    private final AppUser appUser;

    private  OidcIdToken idToken;
    private  OidcUserInfo userInfo;
    private Map<String, Object> attributes;

    public SecurityUser(AppUser appUser) {
        super(appUser.getEmail(), appUser.getPassword(), appUser.isEnabled(), appUser.isAccountNonExpired(), appUser.isCredentialsNonExpired(), appUser.isAccountNonLocked(), appUser.getAuthorities());
        this.appUser = appUser;
    }

    public SecurityUser(AppUser appUser,  OidcIdToken idToken, OidcUserInfo userInfo) {
        super(appUser.getEmail(), appUser.getPassword(), appUser.isEnabled(), appUser.isAccountNonExpired(), appUser.isCredentialsNonExpired(), appUser.isAccountNonLocked(), appUser.getAuthorities());
        this.appUser = appUser;
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    @Override
    public String getName() {
        return this.appUser.getDisplayName();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.attributes;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return this.userInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return this.idToken;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

}
