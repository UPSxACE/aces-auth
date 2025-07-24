package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class GithubEmailDto {
    private final String email;
    private final boolean primary;
    private final boolean verified;
    private final String visibility;
}
