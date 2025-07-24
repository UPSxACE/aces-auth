package com.upsxace.aces_auth_service.features.auth.oauth;

import com.upsxace.aces_auth_service.config.error.BadRequestException;

import java.util.HashMap;
import java.util.Map;

public class OpenIdConnectStrategyManager {
    private final Map<String, OpenIdConnectStrategy> strategies = new HashMap<>();

    public OpenIdConnectStrategyManager(OpenIdConnectStrategy ...strategies){
        for (OpenIdConnectStrategy strategy : strategies) {
            this.strategies.put(strategy.getStrategyName(), strategy);
        }
    }

    public OpenIdConnectStrategy getStrategy(String strategyName){
        var strategy = this.strategies.get(strategyName);
        if(strategy == null){
            throw new BadRequestException("Unknown OAuth2 login strategy.");
        }
        return strategy;
    }
}
