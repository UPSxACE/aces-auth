package com.upsxace.aces_auth_service.features.auth.jwt;

import org.springframework.scheduling.TaskScheduler;

import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryTokenBlacklistService implements  TokenBlacklistService{
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final TaskScheduler taskScheduler;
    private final JwtService jwtService;

    public InMemoryTokenBlacklistService(TaskScheduler taskScheduler, JwtService jwtService) {
        this.taskScheduler = taskScheduler;
        this.jwtService = jwtService;
    }

    @Override
    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    @Override
    public void blacklistToken(String token) {
        try {
            var claims = jwtService.getClaims(token);
            var expirationTime = claims.getExpiration().getTime();

            blacklistedTokens.add(token);

            taskScheduler.schedule(
                    () -> blacklistedTokens.remove(token),
                    new Date(expirationTime).toInstant()
            );
        } catch (Exception ignored){}
    }
}
