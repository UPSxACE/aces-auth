package com.upsxace.aces_auth_service.features.auth.dtos;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class JwtDto {
    private final String accessToken;
}
