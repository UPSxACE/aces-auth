package com.upsxace.aces_auth_service.features.auth.oauth.strategies.dtos;

import lombok.Data;

@Data
public class GoogleIdTokenResponse {
    private final String id_token;
    private final String scope;
}
