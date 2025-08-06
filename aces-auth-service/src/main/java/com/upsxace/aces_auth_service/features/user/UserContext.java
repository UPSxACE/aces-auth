package com.upsxace.aces_auth_service.features.user;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class UserContext {
    private UUID id;
    private List<GrantedAuthority> authorities;

    public boolean hasRole(Role role) {
        return this.authorities.stream().anyMatch(
                a -> a.getAuthority().equals(role.getAuthority())
        );
    }
}
