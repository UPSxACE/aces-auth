package com.upsxace.aces_auth_service.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "config")
@Data
public class AppConfig {
    private String appIdentity;
    private int maxSessions;
    private String frontendUrl;
    private String cookieDomain;
    private Jwt jwt;

    @Data
    public static class Jwt {
        private String secret;
        private long accessTokenExpiration;
        private long refreshTokenExpiration;
    }

    @PostConstruct
    public void validateBean() {
        if (jwt.secret == null || jwt.secret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET environment variable is not set");
        }
    }
}
