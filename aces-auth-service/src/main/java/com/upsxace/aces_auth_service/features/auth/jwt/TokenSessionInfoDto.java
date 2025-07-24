package com.upsxace.aces_auth_service.features.auth.jwt;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.List;

@Data
@RequiredArgsConstructor
public class TokenSessionInfoDto {
    private final String userId;
    private final List<String> authorities;
}
