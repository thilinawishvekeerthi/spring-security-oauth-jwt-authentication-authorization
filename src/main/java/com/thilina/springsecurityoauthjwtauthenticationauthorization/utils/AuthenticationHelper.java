package com.thilina.springsecurityoauthjwtauthenticationauthorization.utils;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.enums.security.SocialProvider;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.model.Role;
import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticationHelper {

    public static List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(final Set<Role> roles) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }

    public static SocialProvider toSocialProvider(String providerId) {
        for (SocialProvider socialProvider : SocialProvider.values()) {
            if (socialProvider.getProviderType().equals(providerId)) {
                return socialProvider;
            }
        }
        return SocialProvider.LOCAL;
    }

//    public static UserInfo buildUserInfo(LocalUser localUser) {
//        List<String> roles = localUser.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
//        User user = localUser.getUser();
//        return new UserInfo(user.getId().toString(), user.getDisplayName(), user.getEmail(), roles);
//    }

    public static void attachAccountId(Authentication authentication, String accountId) {
        Object originalDetails = authentication.getDetails();
        if (originalDetails instanceof Details details) {
            details.setAccountId(accountId);
        } else {
            Details details = new Details()
                    .setOriginal(originalDetails)
                    .setAccountId(accountId);
            ((OAuth2AuthenticationToken) authentication).setDetails(details);
        }
    }

    public static String retrieveAccountId(Authentication authentication) {
        Details details = (Details) authentication.getDetails();
        return details.getAccountId();
    }

    @Data
    @Accessors(chain = true)
    private static class Details {

        private Object original;
        private String accountId;

    }

}
