package com.upsxace.aces_auth_service.features.user;

public enum Role {
    USER,
    ADMIN;

    public String getAuthority(){
        return "ROLE_" + name();
    }
}
