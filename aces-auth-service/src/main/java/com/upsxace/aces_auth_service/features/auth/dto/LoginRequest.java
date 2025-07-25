package com.upsxace.aces_auth_service.features.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Username or email is required.")
    private String identifier;

    @NotBlank(message = "Password is required.")
    private String password;
}
