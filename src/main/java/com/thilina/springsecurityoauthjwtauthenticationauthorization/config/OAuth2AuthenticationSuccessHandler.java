package com.thilina.springsecurityoauthjwtauthenticationauthorization.config;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.service.security.TokenService;
import com.thilina.springsecurityoauthjwtauthenticationauthorization.utils.CookieHelper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.coyote.BadRequestException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import java.net.URI;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final CustomStatelessAuthorizationRequestRepository statelessAuthorizationRequestRepository;
    private final OAuthProperties oAuthProperties;

    private final TokenService tokenService;

    @Override
    @SneakyThrows
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
    @SneakyThrows
    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<Cookie> redirectUriCookie = CookieHelper.getCookie(request,  CookieHelper.REDIRECT_URI_PARAM_COOKIE_NAME);
        String targetUrl = null;
        if(redirectUriCookie.isPresent() ) {
            targetUrl =  CookieHelper.deserialize(redirectUriCookie.get(),String.class);
            if(targetUrl != null && !isAuthorizedRedirectUri(targetUrl))
                throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }else {
            targetUrl = getDefaultTargetUrl();
        }

        String token = tokenService.generateToken(authentication);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("tkn", token)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        statelessAuthorizationRequestRepository.removeAuthorizationRequest(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return oAuthProperties.authorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }


}
