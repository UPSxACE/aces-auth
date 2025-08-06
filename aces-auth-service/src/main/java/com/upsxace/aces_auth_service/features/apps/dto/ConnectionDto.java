package com.upsxace.aces_auth_service.features.apps.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
public class ConnectionDto {
    private final LocalDateTime grantedAt;
    private final List<String> scopes;
    private final ConnectionAppDto app;
}
