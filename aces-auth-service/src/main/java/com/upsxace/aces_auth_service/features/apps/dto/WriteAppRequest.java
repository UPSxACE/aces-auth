package com.upsxace.aces_auth_service.features.apps.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.util.List;

@Data
public class WriteAppRequest {
    @NotBlank(message = "App name must not be blank.")
    @Size(min = 3, max = 100, message = "App name must be between 3 and 100 characters.")
    private final String name;
    @NotEmpty(message = "At least one redirect URI must be provided.")
    private final List<String> redirectUris;
    @NotBlank(message = "Homepage URI must not be blank.")
    @URL(message = "Homepage URI must be a valid URL.")
    private final String homepageUri;
}
