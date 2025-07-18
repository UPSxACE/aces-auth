package com.upsxace.aces_auth_service.features.auth.jwt;

import org.springframework.security.authentication.BadCredentialsException;

public class InvalidSessionException extends BadCredentialsException {
    public InvalidSessionException() {
        super("Invalid session. The session may have expired or been revoked.");
    }
}
