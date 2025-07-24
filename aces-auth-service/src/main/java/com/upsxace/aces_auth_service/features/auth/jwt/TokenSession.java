package com.upsxace.aces_auth_service.features.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@AllArgsConstructor
public class TokenSession {
    private final String refreshToken;
    private final String issuer;
    private final List<String> amr;
    private final String subject;
    private final List<String> authorities;
    private final Date issuedAt;
    private final Date expiresAt;
    private boolean revoked;
    private final int rotationCounter;
    private String cachedAccessToken;
    private Date cachedAccessTokenIssuedAt;
}
