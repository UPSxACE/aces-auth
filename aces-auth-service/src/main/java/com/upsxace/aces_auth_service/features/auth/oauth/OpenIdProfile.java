package com.upsxace.aces_auth_service.features.auth.oauth;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class OpenIdProfile {
    private final String id;
    private final String email;
}
