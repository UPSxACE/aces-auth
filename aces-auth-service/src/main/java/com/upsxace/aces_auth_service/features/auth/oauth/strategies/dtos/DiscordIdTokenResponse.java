package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class DiscordIdTokenResponse {
    private final String scope;
    private final String access_token;
}
