package com.upsxace.aces_auth_service.features.apps;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AppRepository extends JpaRepository<App, UUID> {
    boolean existsByClientId(String clientId);
}
