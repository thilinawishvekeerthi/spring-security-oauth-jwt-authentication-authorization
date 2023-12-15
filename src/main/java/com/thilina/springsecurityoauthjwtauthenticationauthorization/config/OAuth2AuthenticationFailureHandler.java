package com.thilina.springsecurityoauthjwtauthenticationauthorization.config;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.utils.CookieHelper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {


    @Autowired
    CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;

    @Override
    @SneakyThrows
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String targetUrl = CookieHelper.getCookie(request, CookieHelper.REDIRECT_URI_PARAM_COOKIE_NAME).map(Cookie::getValue).orElse(("/"));
        targetUrl = UriComponentsBuilder.fromUriString(targetUrl).queryParam("error", exception.getLocalizedMessage()).build().toUriString();
        customStatelessAuthorizationRequestRepository.removeAuthorizationRequest(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}