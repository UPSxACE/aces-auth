package com.upsxace.aces_auth_service.features.apps.repository;

import com.upsxace.aces_auth_service.features.apps.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByAppClientIdAndUserIdAndAppDeletedAtIsNull(String clientId, UUID userId);
    List<AppUser> findByUserIdAndAppDeletedAtIsNull(UUID userId);
    void deleteByUserIdAndAppClientId(UUID userId, String clientId);
}
