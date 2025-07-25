package com.upsxace.aces_auth_service.features.auth.jwt;

import com.upsxace.aces_auth_service.features.auth.dto.RefreshTokensResult;

import java.util.List;
import java.util.UUID;

public interface TokenSessionManager {
    /**
     * Creates a new token session for the given user.
     *
     * @param userId the id of the user for whom the token session is created
     * @param amr  the list of authentication method references
     * @return the refresh token of the created session
     */
    String createTokenSession(UUID userId, List<String> amr);

    /**
     * Retrieves an access token associated with the given refresh token.
     *
     * @throws InvalidSessionException if the session is invalid or expired
     *
     * @param refreshToken the refresh token
     * @return an access token if the session is valid
     */
    String getAccessToken(String refreshToken) throws InvalidSessionException;

    /**
     * Refreshes the access and refresh tokens (if needed) associated with the given refresh token.
     *
     * @throws InvalidSessionException if the session is invalid or expired
     *
     * @param refreshToken the refresh token
     * @return a RefreshTokensResult containing the fresh access and refresh tokens
     */
    RefreshTokensResult refreshToken(String refreshToken) throws InvalidSessionException;

    /**
     * Revokes the session associated with the given refresh token.
     *
     * @param refreshToken the refresh token
     */
    void revokeTokenSession(String refreshToken);

    /**
     * Retrieves session information that can be shown to user, for the given refresh token.
     *
     * @throws InvalidSessionException if the session is invalid or expired
     *
     * @param refreshToken the refresh token
     * @return TokenSessionInfoDto containing information that can be shown to user
     */
    TokenSessionInfoDto getSessionInfo(String refreshToken) throws InvalidSessionException;

}
