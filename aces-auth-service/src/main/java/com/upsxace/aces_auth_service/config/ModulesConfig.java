package com.upsxace.aces_auth_service.config;

import com.upsxace.aces_auth_service.features.auth.jwt.InMemoryTokenSessionManager;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenSessionManager;
import com.upsxace.aces_auth_service.features.auth.oauth.OpenIdConnectStrategyManager;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.DiscordOidcStrategy;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.GithubOidcStrategy;
import com.upsxace.aces_auth_service.features.auth.oauth.strategies.GoogleOidcStrategy;
import com.upsxace.aces_auth_service.features.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class ModulesConfig {
    private final AppConfig appConfig;

    @Bean
    public TokenSessionManager tokenSessionManager(TaskScheduler taskScheduler, UserService userService, JwtService jwtService) {
        return new InMemoryTokenSessionManager(taskScheduler, appConfig, userService, jwtService);
    }

    @Bean
    public OpenIdConnectStrategyManager openIdConnectStrategyManager(GithubOidcStrategy github, GoogleOidcStrategy google, DiscordOidcStrategy discord){
        return new OpenIdConnectStrategyManager(github, google, discord);
    }
}
