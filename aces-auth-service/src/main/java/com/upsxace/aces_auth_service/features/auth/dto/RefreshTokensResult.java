package com.upsxace.aces_auth_service.features.auth.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class RefreshTokensResult {
    private final String accessToken;
    private final String refreshToken;
}
