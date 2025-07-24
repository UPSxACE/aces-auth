package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class GithubIdTokenResponse {
    private final String access_token;
    private final String scope;
}
