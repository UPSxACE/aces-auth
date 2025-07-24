package com.upsxace.aces_auth_service.features.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserAuthProviderRepository extends JpaRepository<UserAuthProvider, Short> {
    Optional<UserAuthProvider> findByProviderNameAndProviderUserOid(String providerName, String providerUserOidc);
    Optional<UserAuthProvider> findByUserIdAndProviderName(UUID id, String providerName);
}