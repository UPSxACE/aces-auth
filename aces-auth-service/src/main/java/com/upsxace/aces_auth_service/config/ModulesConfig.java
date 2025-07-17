package com.upsxace.aces_auth_service.config;

import com.upsxace.aces_auth_service.features.auth.jwt.InMemoryTokenBlacklistService;
import com.upsxace.aces_auth_service.features.auth.jwt.JwtService;
import com.upsxace.aces_auth_service.features.auth.jwt.TokenBlacklistService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class ModulesConfig {
    @Bean
    public TokenBlacklistService tokenBlacklistService(TaskScheduler taskScheduler, JwtService jwtService) {
        return new InMemoryTokenBlacklistService(taskScheduler, jwtService);
    }
}
