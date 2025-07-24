package com.upsxace.aces_auth_service.features.auth.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OpenIdConnectContext {
    private final OpenIdConnectStrategyManager strategyManager;

    public OpenIdProfile authenticate(String strategyName, String code, String codeVerifier, String redirectUri) {
        var strategy = strategyManager.getStrategy(strategyName);
        var accessToken = strategy.getToken(code, codeVerifier, redirectUri);
        return strategy.getOpenIdProfile(accessToken);
    }
}
