package com.upsxace.aces_auth_service.features.auth.oauth;

public interface OpenIdConnectStrategy {
    String getStrategyName();
    String getToken(String code, String codeVerifier, String redirectUri);
    OpenIdProfile getOpenIdProfile(String token);
}
