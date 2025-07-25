package com.upsxace.aces_auth_service.features.auth.dto;

import com.upsxace.aces_auth_service.common.validation.ValidFullName;
import com.upsxace.aces_auth_service.common.validation.ValidPassword;
import com.upsxace.aces_auth_service.common.validation.ValidUsername;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterByEmailRequest {
    @NotBlank(message = "Username is required.")
    @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters.")
    @ValidUsername
    private String username;

    @NotBlank(message = "Email is required.")
    @Email(message = "Email must be a valid email address.")
    @Size(max = 255, message = "Email must be 255 characters or fewer.")
    private String email;

    @NotBlank(message = "Name is required.")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters.")
    @ValidFullName
    private String name;

    @NotBlank(message = "Password is required.")
    @Size(min = 9, max = 128, message = "Password must be between 9 and 128 characters.")
    @ValidPassword
    private String password;
}