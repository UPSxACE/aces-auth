package com.upsxace.aces_auth_service.features.apps;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByAppClientIdAndUserIdAndAppDeletedAtIsNull(String clientId, UUID uuid);
}
