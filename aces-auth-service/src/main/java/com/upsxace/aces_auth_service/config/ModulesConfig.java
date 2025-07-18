package com.upsxace.aces_auth_service.config;

import com.upsxace.aces_auth_service.features.auth.jwt.InMemoryTokenSessionManager;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenSessionManager;
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
    public TokenSessionManager tokenSessionManager(TaskScheduler taskScheduler, JwtService jwtService) {
        return new InMemoryTokenSessionManager(taskScheduler, appConfig, jwtService);
    }
}
