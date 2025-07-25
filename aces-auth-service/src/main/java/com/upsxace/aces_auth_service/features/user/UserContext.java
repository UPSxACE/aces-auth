package com.upsxace.aces_auth_service.features.user;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.UUID;

@Data
@RequiredArgsConstructor
public class UserContext {
    private final UUID id;
    private final List<GrantedAuthority> authorities;

    public boolean hasRole(Role role) {
        return this.authorities.stream().anyMatch(
                a -> a.getAuthority().equals(role.getAuthority())
        );
    }
}
