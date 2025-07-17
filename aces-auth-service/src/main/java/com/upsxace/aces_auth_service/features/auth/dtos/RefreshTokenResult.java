package com.upsxace.aces_auth_service.features.auth.dtos;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class RefreshTokenResult {
    private final String accessToken;
    private final String refreshToken;
}
