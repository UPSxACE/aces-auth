package com.upsxace.aces_auth_service.features.auth.jwt;

public interface TokenBlacklistService {
    /**
     * Checks if a token is blacklisted.
     *
     * @param token the JWT token to check
     * @return true if the token is blacklisted, false otherwise
     */
    boolean isBlacklisted(String token);

    /**
     * Blacklists a given JWT token.
     *
     * @param token the JWT token to blacklist
     */
    void blacklistToken(String token);
}
