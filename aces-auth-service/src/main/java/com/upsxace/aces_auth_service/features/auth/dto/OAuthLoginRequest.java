package com.upsxace.aces_auth_service.features.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OAuthLoginRequest {
    @NotBlank(message = "Code is required.")
    private String code;

    @NotBlank(message = "Code verifier is required.")
    private String codeVerifier;

    @NotBlank(message = "Redirect uri is required.")
    private String redirectUri;
}
