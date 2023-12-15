package com.thilina.springsecurityoauthjwtauthenticationauthorization.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "app.oauth")
public record OAuthProperties(List<String> authorizedRedirectUris) {
}
