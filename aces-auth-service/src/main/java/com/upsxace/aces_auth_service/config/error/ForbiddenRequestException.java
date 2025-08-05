package com.upsxace.aces_auth_service.config.error;

public class ForbiddenRequestException extends RuntimeException {
    public ForbiddenRequestException() {
        super("Forbidden.");
    }

    public ForbiddenRequestException(String message) {
        super(message);
    }
}