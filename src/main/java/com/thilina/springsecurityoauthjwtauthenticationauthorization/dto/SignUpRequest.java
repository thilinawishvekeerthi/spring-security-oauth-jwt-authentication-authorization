package com.thilina.springsecurityoauthjwtauthenticationauthorization.dto;

import com.thilina.springsecurityoauthjwtauthenticationauthorization.enums.security.SocialProvider;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class SignUpRequest {
    public SignUpRequest(){}

    private Long userID;

    private String providerUserId;

    @NotEmpty
    private String displayName;

    @NotEmpty
    private String email;

    private SocialProvider socialProvider;

    @Size(min = 6, message = "{Size.userDto.password}")
    private String password;

    @NotEmpty
    private String matchingPassword;
}
