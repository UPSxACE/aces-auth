package com.upsxace.aces_auth_service.features.apps.entity;

import com.upsxace.aces_auth_service.features.user.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@Table(name = "app_user")
@Entity
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "app_id")
    private App app;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "granted_at")
    private LocalDateTime grantedAt;

    @Column(name = "scopes")
    private String scopes;

    public List<String> getScopesList(){
        return Arrays.stream(this.scopes.split(" ")).collect(Collectors.toList());
    }
}