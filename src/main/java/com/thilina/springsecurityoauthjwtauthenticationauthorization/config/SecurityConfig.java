package com.thilina.springsecurityoauthjwtauthenticationauthorization.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityUserDetailsService userDetailsService;
    private final CustomStatelessAuthorizationRequestRepository statelessAuthorizationRequestRepository;
    private final CustomOidcUserService customOidcUserService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(Customizer.withDefaults())
                .csrf(csrf->csrf.disable())
                .formLogin(login->login.disable())
                .httpBasic(basic->basic.disable())
                .sessionManagement(config->config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(sever->sever.jwt(Customizer.withDefaults()))
//                .httpBasic(Customizer.withDefaults())
                .exceptionHandling(exc->exc.authenticationEntryPoint(new RestAuthenticationEntryPoint()))
                .authorizeHttpRequests(
                        auth->{
                            auth.requestMatchers("/h2-console/**", "/oauth2/**")// use only in developer mode move to sql db like postgres, mysql, oracle
                                    .permitAll()
                                    .anyRequest()
                                    .authenticated();
                        }
                )
                .userDetailsService(userDetailsService)
                .headers(headers->headers.frameOptions(fo->fo.sameOrigin())) // added to enable h2 console
                .oauth2Login(config -> {
                    config.authorizationEndpoint(subConfig -> {
                        subConfig.authorizationRequestRepository(this.statelessAuthorizationRequestRepository);
                    });
                    config.userInfoEndpoint(subConfig->{
                        subConfig.oidcUserService(customOidcUserService);
                        subConfig.userService(customOAuth2UserService);
                    });
                    config.successHandler(oAuth2AuthenticationSuccessHandler);
                    config.failureHandler(oAuth2AuthenticationFailureHandler);
                }
                )
                .build();
    }





}
