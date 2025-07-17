package com.upsxace.aces_auth_service.features.user.dtos;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class UserProfileDto {
    private UUID id;
    private String username;
    private String email;
    private String name;
    private LocalDateTime createdAt;
}
