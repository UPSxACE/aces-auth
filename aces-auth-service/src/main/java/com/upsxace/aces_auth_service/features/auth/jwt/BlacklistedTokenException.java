package com.upsxace.aces_auth_service.features.auth.jwt;

import org.springframework.security.authentication.BadCredentialsException;

public class BlacklistedTokenException extends BadCredentialsException {
    public BlacklistedTokenException() {
        super("Refresh token is blacklisted");
    }
}
