package com.upsxace.aces_auth_service.features.auth;

import com.upsxace.aces_auth_service.features.user.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Getter
@Setter
@Table(name = "user_auth_provider")
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserAuthProvider {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Short id;

    @Column(name = "provider_name")
    private String providerName;

    @Column(name = "provider_user_oid")
    private String providerUserOid;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;
}