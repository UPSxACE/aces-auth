package com.upsxace.aces_auth_service.features.apps.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
public class AppDto {
    private final UUID id;
    private final String name;
    private final String clientId;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String clientSecret;
    private final List<String> redirectUris;
    private final String homepageUrl;
    private final LocalDateTime createdAt;

    public AppDto removeCredentials(){
        this.clientSecret = null;
        return this;
    }
}
