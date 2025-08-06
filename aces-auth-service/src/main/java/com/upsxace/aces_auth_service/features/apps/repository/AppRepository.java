package com.upsxace.aces_auth_service.features.apps.repository;

import com.upsxace.aces_auth_service.features.apps.entity.App;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppRepository extends JpaRepository<App, UUID> {
    Optional<App> findByIdAndDeletedAtIsNull(UUID id);
    boolean existsByClientIdAndDeletedAtIsNull(String clientId);
    Optional<App> findByClientIdAndDeletedAtIsNull(String clientId);
    List<App> findByOwnerIdAndDeletedAtIsNullOrderByCreatedAtDesc(UUID id);
    Optional<App> findByIdAndOwnerIdAndDeletedAtIsNull(UUID clientId, UUID ownerId);
}
