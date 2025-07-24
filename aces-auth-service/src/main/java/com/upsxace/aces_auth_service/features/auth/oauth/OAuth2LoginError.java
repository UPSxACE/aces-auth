package com.upsxace.aces_auth_service.features.auth.oauth;

import com.upsxace.aces_auth_service.config.error.BadRequestException;

public class OAuth2LoginError extends BadRequestException {
    public OAuth2LoginError() {
        super("Failed to login.");
    }

    public OAuth2LoginError(String message) {
        super(message);
    }
}
