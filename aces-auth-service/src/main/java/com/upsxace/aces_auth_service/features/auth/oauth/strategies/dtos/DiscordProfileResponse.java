package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class DiscordProfileResponse {
    private final String id;
    private final String email;
}
