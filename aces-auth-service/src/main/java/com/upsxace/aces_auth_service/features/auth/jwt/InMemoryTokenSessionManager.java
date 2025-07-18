package com.upsxace.aces_auth_service.features.auth.jwt;

import com.upsxace.aces_auth_service.config.AppConfig;
import com.upsxace.aces_auth_service.features.auth.dtos.RefreshTokensResult;
import org.springframework.scheduling.TaskScheduler;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

public class InMemoryTokenSessionManager implements TokenSessionManager {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    private final Map<String, TokenSession> tokenSessions = new ConcurrentHashMap<>();
    private final Map<String, ScheduledFuture<?>> scheduledRemovals = new ConcurrentHashMap<>();

    private final AppConfig appConfig;
    private final JwtService jwtService;
    private final TaskScheduler taskScheduler;

    public InMemoryTokenSessionManager(TaskScheduler taskScheduler, AppConfig appConfig,  JwtService jwtService) {
        this.taskScheduler = taskScheduler;
        this.appConfig = appConfig;
        this.jwtService = jwtService;
    }

    private String generateRefreshToken() {
        String refreshToken;
        do {
            var randomBytes = new byte[32]; // 256 bits
            secureRandom.nextBytes(randomBytes);
            refreshToken = base64Encoder.encodeToString(randomBytes);
        } while (tokenSessions.containsKey(refreshToken));
        return refreshToken;
    }

    private void saveTokenSession(TokenSession session) {
        tokenSessions.put(session.getRefreshToken(), session);
        scheduledRemovals.put(session.getRefreshToken(), taskScheduler.schedule(
                () -> {
                    tokenSessions.remove(session.getRefreshToken());
                    scheduledRemovals.remove(session.getRefreshToken());
                },
                session.getExpiresAt().toInstant()
        ));
    }

    @Override
    public String createTokenSession(UUID userId, List<AuthenticationMethodReference> amr) {
        var refreshToken = generateRefreshToken();

        final long TOKEN_EXPIRATION_MS = appConfig.getJwt().getRefreshTokenExpiration() * 1000;

        var tokenSession = new TokenSession(
                refreshToken,
                appConfig.getAppIdentity(),
                amr,
                userId.toString(),
                new Date(),
                new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_MS),
                false,
                0,
                jwtService.generateTokenForUser(userId, amr),
                new Date()
        );

        saveTokenSession(tokenSession);

        return refreshToken;
    }

    private TokenSession getSession(String refreshToken) throws InvalidSessionException {
        TokenSession session = tokenSessions.get(refreshToken);
        if (session == null || session.isRevoked() || session.getExpiresAt().before(new Date())) {
            throw new InvalidSessionException();
        }
        return session;
    }

    public String getAccessToken(TokenSession session) {
        synchronized (session) {
            var cachedToken = session.getCachedAccessToken();
            if (cachedToken != null)
                return cachedToken;

            var newAccessToken = jwtService.generateTokenForUser(UUID.fromString(session.getSubject()), session.getAmr());
            session.setCachedAccessToken(newAccessToken);
            session.setCachedAccessTokenIssuedAt(new Date());

            return newAccessToken;
        }
    }

    @Override
    public String getAccessToken(String refreshToken) {
        var session = getSession(refreshToken);
        return getAccessToken(session);
    }

    private boolean shouldRenewToken(Date expiration, long lifetimeInSeconds) {
        long threshold = lifetimeInSeconds * 1000 * 2 / 3;
        Date renewalDate = new Date(expiration.getTime() - threshold);
        return new Date().after(renewalDate);
    }

    @Override
    public RefreshTokensResult refreshToken(String refreshToken) {
        final long REFRESH_TOKEN_EXPIRATION_MS = appConfig.getJwt().getRefreshTokenExpiration() * 1000;
        final long ACCESS_TOKEN_EXPIRATION_MS = appConfig.getJwt().getAccessTokenExpiration() * 1000;

        var session = getSession(refreshToken);

        synchronized (session) {
            // Refresh session if refresh token is older than 2/3 of its lifetime
            if(shouldRenewToken(session.getExpiresAt(), appConfig.getJwt().getRefreshTokenExpiration())){
                var scheduledRemoval = scheduledRemovals.remove(refreshToken);
                if(scheduledRemoval != null) {
                    scheduledRemoval.cancel(false);
                }

                tokenSessions.remove(refreshToken);

                var newSession = new TokenSession(
                        generateRefreshToken(),
                        appConfig.getAppIdentity(),
                        session.getAmr(),
                        session.getSubject(),
                        new Date(),
                        new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_MS),
                        false,
                        session.getRotationCounter() + 1,
                        jwtService.generateTokenForUser(UUID.fromString(session.getSubject()), session.getAmr()),
                        new Date()
                );

                saveTokenSession(newSession);

                return new RefreshTokensResult(newSession.getCachedAccessToken(), newSession.getRefreshToken());
            }

            var cachedAccessToken = getAccessToken(session);
            var cachedAccessTokenIssuedAt = session.getCachedAccessTokenIssuedAt();
            var cachedAccessTokenExpiration = new Date(cachedAccessTokenIssuedAt.getTime() + ACCESS_TOKEN_EXPIRATION_MS);
            // Refresh the access token if it is older than 2/3 of its lifetime
            if (shouldRenewToken(cachedAccessTokenExpiration, appConfig.getJwt().getAccessTokenExpiration())) {
                cachedAccessToken = jwtService.generateTokenForUser(UUID.fromString(session.getSubject()), session.getAmr());
                session.setCachedAccessToken(cachedAccessToken);
                session.setCachedAccessTokenIssuedAt(new Date());
            }

            return new RefreshTokensResult(cachedAccessToken, session.getRefreshToken());
        }
    }



    @Override
    public void revokeTokenSession(String refreshToken) {
        var session = tokenSessions.get(refreshToken);
        if(session != null){
            synchronized (session) {
                session.setRevoked(true);
            }
        }
    }
}
